#!/usr/bin/env python3
"""Fast repository control plane for ecommerce-1.

This program replaces stateless shell wrappers. It performs no cloud deployment and
never becomes a CI authority: Tekton remains authoritative. Stateful workstation and
toolchain reconciliation belongs to platform/ansible/developer.yml.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import math
import os
from pathlib import Path
import re
import signal
import shutil
import subprocess
import sys
import tempfile
import time

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))


def _missing_repository_delivery(*_args, **_kwargs):
    raise RuntimeError(
        "repository delivery helper unavailable: scripts/repository_delivery.py is required "
        "for delivery/evidence/Tekton commands"
    )


try:
    from repository_delivery import (
        bundle_deliver as isolated_bundle_deliver,
        compare_evidence,
        evidence_metrics,
        fetch_evidence,
        publish_evidence,
        publish_remote_status,
        REMOTE_STATUS_CONTEXT,
    )
except ModuleNotFoundError as exc:
    if exc.name != "repository_delivery":
        raise
    isolated_bundle_deliver = _missing_repository_delivery
    compare_evidence = _missing_repository_delivery
    evidence_metrics = _missing_repository_delivery
    fetch_evidence = _missing_repository_delivery
    publish_evidence = _missing_repository_delivery
    publish_remote_status = _missing_repository_delivery
    REMOTE_STATUS_CONTEXT = "tekton/ecommerce-affected"

ROOT = Path(subprocess.check_output(["git", "rev-parse", "--show-toplevel"], text=True).strip())


def _raw_toolchain_lock() -> dict:
    return json.loads((ROOT / "config/contracts/toolchain-lock.json").read_text(encoding="utf-8"))


def managed_bin_dirs() -> tuple[Path, ...]:
    contract = _raw_toolchain_lock()
    policy = contract.get("capability_policy", {})
    relatives = policy.get("managed_bin_subdirectories", [])
    if not isinstance(relatives, list) or not relatives or any(not isinstance(item, str) or not item for item in relatives):
        raise RuntimeError("central toolchain lock must declare managed_bin_subdirectories")
    return tuple(Path.home() / item for item in relatives)


def toolchain_projection_path(name: str) -> Path:
    projection = _raw_toolchain_lock().get("projections", {}).get(name, {})
    relative = projection.get("path") if isinstance(projection, dict) else None
    if not isinstance(relative, str) or not relative:
        raise RuntimeError(f"central toolchain lock missing projection path: {name}")
    return ROOT / relative


def ansible_collections_root() -> Path:
    config = _raw_toolchain_lock().get("native_tool_configs", {}).get("ansible", {})
    relative = config.get("collections_install_root") if isinstance(config, dict) else None
    if not isinstance(relative, str) or not relative:
        raise RuntimeError("central toolchain lock missing Ansible collections_install_root")
    return ROOT / relative


os.environ["PATH"] = f"{os.pathsep.join(str(path) for path in managed_bin_dirs())}{os.pathsep}{os.environ.get('PATH', '')}"
PROJECT_COLLECTIONS = ansible_collections_root()
# Every Ansible subprocess resolves collections from the project-owned path only.
# This prevents a user or distro installation from silently changing execution.
os.environ["ANSIBLE_COLLECTIONS_PATH"] = str(PROJECT_COLLECTIONS)
os.environ["ANSIBLE_CONFIG"] = str(toolchain_projection_path("ansible_config"))
CONTEXT = ROOT / ".context"


class MissingRunnerPrerequisite(RuntimeError):
    """A runner-owned primitive is absent; repository code must not install it."""


def fail(message: str, code: int = 2) -> int:
    print(f"FAIL {message}", file=sys.stderr)
    return code


def require(name: str) -> str:
    path = shutil.which(name)
    if not path:
        if name == "ruby":
            raise MissingRunnerPrerequisite(f"runner prerequisite missing: {name}")
        raise RuntimeError(f"required command missing: {name}")
    return path


def run(
    cmd: list[str],
    *,
    cwd: Path | None = None,
    env: dict[str, str] | None = None,
    check: bool = True,
    capture: bool = False,
) -> subprocess.CompletedProcess[str]:
    p = subprocess.run(
        cmd,
        cwd=cwd or ROOT,
        env=env,
        text=True,
        stdout=subprocess.PIPE if capture else None,
        stderr=subprocess.PIPE if capture else None,
    )
    if check and p.returncode:
        detail = (p.stderr or p.stdout or "").strip()
        raise RuntimeError(detail or f"command failed ({p.returncode}): {' '.join(cmd)}")
    return p


def output(cmd: list[str], *, cwd: Path | None = None, env: dict[str, str] | None = None) -> str:
    return run(cmd, cwd=cwd, env=env, capture=True).stdout


def git(*args: str, check: bool = True) -> str:
    p = run(["git", *args], check=check, capture=True)
    return p.stdout


def ruby_yaml(path: str) -> dict:
    require("ruby")
    script = "require 'yaml'; require 'json'; d=YAML.safe_load(File.read(ARGV[0]), aliases: false) || {}; print JSON.generate(d)"
    result = subprocess.run(
        ["ruby", "-e", script, path],
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if result.returncode:
        raise RuntimeError((result.stderr or result.stdout or "").strip() or f"Ruby YAML parse failed: {path}")
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"Ruby YAML parser returned invalid JSON for {path}") from exc


_SOURCE_QUALITY_POLICY: dict | None = None


def source_quality_policy() -> dict:
    """Load the single repository-wide source quality contract."""
    global _SOURCE_QUALITY_POLICY
    if _SOURCE_QUALITY_POLICY is None:
        lock = ruby_yaml("architecture.lock.yaml")
        relative = lock.get("machine_contracts", {}).get("source_quality_policy")
        if not isinstance(relative, str) or not relative.strip():
            raise RuntimeError("architecture.lock.yaml must register machine_contracts.source_quality_policy")
        policy = ruby_yaml(relative)
        if policy.get("architecture_authority") != "architecture.lock.yaml" or policy.get("scope") != "entire-repository":
            raise RuntimeError("source quality policy must inherit architecture.lock.yaml for the entire repository")

        adapters = policy.get("orchestration_adapters", {})
        pre_commit = adapters.get("pre_commit", {})
        pre_commit_path = pre_commit.get("path")
        required_delegate = pre_commit.get("required_delegate")
        if pre_commit_path and required_delegate:
            adapter_path = ROOT / str(pre_commit_path)
            if not adapter_path.is_file() or str(required_delegate) not in adapter_path.read_text(encoding="utf-8"):
                raise RuntimeError("pre-commit adapter must delegate to the central repoctl quality authority")

        _SOURCE_QUALITY_POLICY = policy
    return copy.deepcopy(_SOURCE_QUALITY_POLICY)


_REPOSITORY_AUTHORITY_MODEL: dict | None = None
_SECURITY_SCAN_POLICY: dict | None = None
_WORKSTATION_POLICY: dict | None = None


def repository_authority_model() -> dict:
    global _REPOSITORY_AUTHORITY_MODEL
    if _REPOSITORY_AUTHORITY_MODEL is None:
        lock = ruby_yaml("architecture.lock.yaml")
        relative = lock.get("machine_contracts", {}).get("repository_authority_model")
        if not isinstance(relative, str) or not relative.strip():
            raise RuntimeError("architecture.lock.yaml must register machine_contracts.repository_authority_model")
        model = ruby_yaml(relative)
        if (
            model.get("architecture_authority") != "architecture.lock.yaml"
            or model.get("scope") != "entire-repository"
            or model.get("status") != "exact"
        ):
            raise RuntimeError("repository authority model must inherit architecture.lock.yaml for the entire repository")
        _REPOSITORY_AUTHORITY_MODEL = model
    return copy.deepcopy(_REPOSITORY_AUTHORITY_MODEL)


def workstation_policy() -> dict:
    global _WORKSTATION_POLICY
    if _WORKSTATION_POLICY is None:
        lock = ruby_yaml("architecture.lock.yaml")
        relative = lock.get("machine_contracts", {}).get("workstation_policy")
        if not isinstance(relative, str) or not relative.strip():
            raise RuntimeError("architecture.lock.yaml must register machine_contracts.workstation_policy")
        policy = ruby_yaml(relative)
        if (
            policy.get("architecture_authority") != "architecture.lock.yaml"
            or policy.get("scope") != "developer-workstation"
            or policy.get("status") != "exact"
        ):
            raise RuntimeError("workstation policy must inherit architecture.lock.yaml")
        _WORKSTATION_POLICY = policy
    return copy.deepcopy(_WORKSTATION_POLICY)


def security_scan_policy() -> dict:
    global _SECURITY_SCAN_POLICY
    if _SECURITY_SCAN_POLICY is None:
        lock = ruby_yaml("architecture.lock.yaml")
        relative = lock.get("machine_contracts", {}).get("security_scan_policy")
        if not isinstance(relative, str) or not relative.strip():
            raise RuntimeError("architecture.lock.yaml must register machine_contracts.security_scan_policy")
        policy = ruby_yaml(relative)
        if (
            policy.get("architecture_authority") != "architecture.lock.yaml"
            or policy.get("scope") != "entire-repository"
            or policy.get("status") != "exact"
        ):
            raise RuntimeError("security scan policy must inherit architecture.lock.yaml for the entire repository")
        _SECURITY_SCAN_POLICY = policy
    return copy.deepcopy(_SECURITY_SCAN_POLICY)


def write_gitleaks_policy_config(path: Path, policy: dict | None = None) -> None:
    contract = policy or security_scan_policy()
    config = contract.get("configuration", {})
    allowlist = config.get("allowlist", {})
    patterns = allowlist.get("paths", [])
    if not isinstance(patterns, list) or any(not isinstance(item, str) for item in patterns):
        raise RuntimeError("security scan allowlist paths must be strings")
    lines = [
        'title = "Generated from central security-scan-policy"',
        "",
        "[extend]",
        f"useDefault = {'true' if config.get('use_default_rules') is True else 'false'}",
        "",
        "[allowlist]",
        f"description = {json.dumps(str(allowlist.get('description', '')))}",
        "paths = [",
    ]
    lines.extend(f"  {json.dumps(pattern)}," for pattern in patterns)
    lines.extend(["]", ""])
    path.write_text("\n".join(lines), encoding="utf-8")


def validate_workstation_projections(policy: dict | None = None) -> None:
    contract = policy or workstation_policy()

    git_contract = contract.get("git", {})
    git_path = ROOT / str(git_contract.get("projection", ""))
    git_actual: dict[str, str] = {}
    for raw in git_path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        git_actual[key.strip()] = value.strip()
    git_expected = {str(key): str(value) for key, value in git_contract.get("settings", {}).items()}
    if git_actual != git_expected:
        raise RuntimeError("config/workstation/git-local.conf drifted from central workstation policy")

    wsl_contract = contract.get("wsl2", {})
    wsl_path = ROOT / str(wsl_contract.get("projection", ""))
    wsl_actual: dict[str, str] = {}
    for raw in wsl_path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("[") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        wsl_actual[key.strip()] = value.strip()
    wsl_expected = {str(key): str(value) for key, value in wsl_contract.get("settings", {}).items()}
    if wsl_actual != wsl_expected:
        raise RuntimeError("config/workstation/wslconfig.template drifted from central workstation policy")

    winget_contract = contract.get("winget", {})
    winget_path = ROOT / str(winget_contract.get("projection", ""))
    winget = ruby_yaml(str(winget_path))
    resources = winget.get("resources", [])
    actual_packages = {}
    for resource in resources:
        if not isinstance(resource, dict) or resource.get("type") != "Microsoft.WinGet/Package":
            continue
        properties = resource.get("properties", {})
        actual_packages[str(resource.get("name"))] = {
            "id": str(properties.get("id")),
            "source": str(properties.get("source")),
            "useLatest": properties.get("useLatest"),
        }
    expected_packages = {
        str(name): {
            "id": str(values.get("id")),
            "source": str(values.get("source")),
            "useLatest": winget_contract.get("package_policy") == "latest-platform-provided",
        }
        for name, values in winget_contract.get("packages", {}).items()
    }
    if actual_packages != expected_packages:
        raise RuntimeError(".config/configuration.winget drifted from central workstation policy")


def validate_terraform_lockfile_projections(provider_contract: dict | None = None) -> None:
    """Verify committed Terraform lockfiles project the canonical provider identity."""
    contract = provider_contract or terraform_provider_lock_contract()
    expected = contract.get("providers", {})
    lockfiles = (
        ROOT / "platform/terraform/environments/mgmt/.terraform.lock.hcl",
        ROOT / "platform/terraform/environments/qualification/.terraform.lock.hcl",
    )
    for lockfile in lockfiles:
        text = lockfile.read_text(encoding="utf-8")
        for name, provider in expected.items():
            source = str(provider["source"])
            version = str(provider["version"])
            hashes = {str(value) for value in provider["hashes"]}
            block_match = re.search(
                rf'provider\s+"{re.escape(source)}"\s*\{{(?P<body>.*?)\n\}}',
                text,
                re.DOTALL,
            )
            if not block_match:
                raise RuntimeError(f"{lockfile.relative_to(ROOT)} missing canonical provider {source}")
            body = block_match.group("body")
            version_match = re.search(r'^\s*version\s*=\s*"([^"]+)"\s*$', body, re.MULTILINE)
            if not version_match or version_match.group(1) != version:
                raise RuntimeError(
                    f"{lockfile.relative_to(ROOT)} provider {name} version drifted from central lock"
                )
            actual_hashes = set(re.findall(r'"((?:h1|zh):[^"]+)"', body))
            if actual_hashes != hashes:
                raise RuntimeError(
                    f"{lockfile.relative_to(ROOT)} provider {name} hashes drifted from central lock"
                )


def repository_authority_check() -> int:
    """Validate the repository-wide authority hierarchy and all declared projections."""
    lock = ruby_yaml("architecture.lock.yaml")
    registry = lock.get("machine_contracts", {})
    if not isinstance(registry, dict):
        raise RuntimeError("architecture.lock.yaml machine_contracts must be a mapping")

    model = repository_authority_model()
    for domain, entry in model.get("domains", {}).items():
        if not isinstance(entry, dict):
            raise RuntimeError(f"repository authority domain {domain} must be a mapping")
        machine_contract = entry.get("machine_contract")
        if machine_contract:
            if machine_contract not in registry:
                raise RuntimeError(f"repository authority domain {domain} references missing machine contract {machine_contract}")
            if not (ROOT / str(registry[machine_contract])).is_file():
                raise RuntimeError(f"repository authority domain {domain} contract path is missing")

    for relative in model.get("forbidden_parallel_policy_files", []):
        if (ROOT / str(relative)).exists():
            raise RuntimeError(f"parallel local policy is forbidden by repository authority model: {relative}")

    for projection in model.get("native_projections", []):
        if not isinstance(projection, dict):
            raise RuntimeError("repository native projection entries must be mappings")
        relative = projection.get("path")
        authority = projection.get("authority")
        if not isinstance(relative, str) or not relative or not (ROOT / relative).is_file():
            raise RuntimeError(f"repository projection missing: {relative!r}")
        if not isinstance(authority, str) or "machine_contracts." not in authority:
            raise RuntimeError(f"repository projection {relative} must name a machine-contract authority")
        authority_key = authority.split("machine_contracts.", 1)[1].split("#", 1)[0].split(".", 1)[0]
        if authority_key not in registry:
            raise RuntimeError(f"repository projection {relative} references unknown authority {authority_key}")

    for adapter in model.get("orchestration_adapters", []):
        relative = adapter.get("path") if isinstance(adapter, dict) else None
        if not isinstance(relative, str) or not (ROOT / relative).is_file():
            raise RuntimeError(f"repository orchestration adapter missing: {relative!r}")
        content = (ROOT / relative).read_text(encoding="utf-8")
        if "repoctl.py" not in content:
            raise RuntimeError(f"repository orchestration adapter must delegate to repoctl: {relative}")
        for marker in adapter.get("forbidden_markers", []):
            if not isinstance(marker, str) or not marker:
                raise RuntimeError(f"repository orchestration adapter {relative} has invalid forbidden marker")
            if marker in content:
                raise RuntimeError(f"repository orchestration adapter contains local policy marker {marker!r}: {relative}")

    for manifest in model.get("component_manifests", []):
        pattern = manifest.get("pattern") if isinstance(manifest, dict) else None
        if not isinstance(pattern, str) or not list(ROOT.glob(pattern)):
            raise RuntimeError(f"component manifest pattern has no repository matches: {pattern!r}")

    from capability_bootstrap import load_contract, load_toolchain_lock, validate_contract, validate_toolchain_projections

    toolchain = load_toolchain_lock()
    validate_toolchain_projections(toolchain)
    capability_graph = load_contract()
    validate_contract(capability_graph, toolchain["versions"])

    capability_policy = toolchain.get("capability_policy", {})
    if capability_graph.get("supported") != capability_policy.get("supported"):
        raise RuntimeError("capability graph supported platforms drifted from central toolchain lock")
    allowed_provision_types = set(capability_policy.get("managed_provision_types", []))
    for capability, owner in capability_graph.get("provision_owners", {}).items():
        if owner not in allowed_provision_types:
            raise RuntimeError(
                f"capability {capability} uses provision owner {owner!r} outside central toolchain policy"
            )

    go_policy = toolchain.get("language_contracts", {}).get("go", {})
    expected_go_directive = str(go_policy.get("workspace_language_directive", ""))
    if expected_go_directive:
        go_manifests = [ROOT / "go.work", ROOT / "frontend" / "go.mod"]
        go_manifests.extend(sorted((ROOT / "services").glob("*/go.mod")))
        for manifest in go_manifests:
            text = manifest.read_text(encoding="utf-8")
            match = re.search(r"^go\s+([0-9.]+)\s*$", text, re.MULTILINE)
            if not match or match.group(1) != expected_go_directive:
                raise RuntimeError(
                    f"{manifest.relative_to(ROOT)} Go directive must project central language version {expected_go_directive}"
                )

        workspace = (ROOT / "go.work").read_text(encoding="utf-8")
        use_block = re.search(r"(?ms)^use\s*\((?P<body>.*?)^\)", workspace)
        if not use_block:
            raise RuntimeError("go.work must use the canonical multi-module workspace block")
        actual_modules = {
            line.strip().removeprefix("./")
            for line in use_block.group("body").splitlines()
            if line.strip() and not line.strip().startswith("//")
        }
        expected_modules = {str(lock["business"]["frontend_runtime"]["module"])}
        expected_modules.update(f"services/{service}" for service in lock["business"]["services"])
        if actual_modules != expected_modules:
            raise RuntimeError(
                "go.work module set must match architecture.lock.yaml business services and frontend module"
            )

    templ_version = toolchain["versions"].get("TEMPL_VERSION")
    frontend_go_mod = (ROOT / "frontend" / "go.mod").read_text(encoding="utf-8")
    if templ_version and f"github.com/a-h/templ v{templ_version}" not in frontend_go_mod:
        raise RuntimeError("frontend/go.mod templ version drifted from central toolchain lock")

    validate_workstation_projections()
    validate_terraform_lockfile_projections()

    security_policy = security_scan_policy()
    scanner = security_policy.get("scanner", {})
    version_key = scanner.get("version_key")
    checksum_key = scanner.get("checksum_key")
    for key in (version_key, checksum_key):
        if not isinstance(key, str) or key not in toolchain["versions"]:
            raise RuntimeError(f"security scan policy references missing toolchain key: {key!r}")

    print("PASS repository maximal authority model")
    return 0


def source_quality_adapter(name: str) -> dict:
    adapter = source_quality_policy().get("adapters", {}).get(name)
    if not isinstance(adapter, dict):
        raise RuntimeError(f"source quality adapter is not declared: {name}")
    return adapter


def advisory_exit_check(
    label: str,
    command: list[str],
    *,
    drift_exit_codes: list[int],
    cwd: Path | None = None,
    env: dict[str, str] | None = None,
) -> None:
    """Run a read-only formatter check; only declared drift exits are advisory."""
    result = run(command, cwd=cwd, env=env, check=False, capture=True)
    output_text = ((result.stdout or "") + (result.stderr or "")).strip()
    if result.returncode == 0:
        return
    if result.returncode in {int(code) for code in drift_exit_codes}:
        if output_text:
            print(output_text, file=sys.stderr)
        print(f"ADVISORY {label}: source formatting drift detected", file=sys.stderr)
        return
    raise RuntimeError(output_text or f"{label} formatter failed with exit code {result.returncode}")


def advisory_output_check(label: str, output_text: str) -> None:
    """Report formatter drift that is signaled by non-empty output."""
    if output_text.strip():
        print(output_text.strip(), file=sys.stderr)
        print(f"ADVISORY {label}: source formatting drift detected", file=sys.stderr)


_TERRAFORM_PROVIDER_LOCK: dict | None = None


def terraform_provider_lock_contract() -> dict:
    """Load and validate the single canonical Terraform provider lock contract."""
    global _TERRAFORM_PROVIDER_LOCK
    if _TERRAFORM_PROVIDER_LOCK is None:
        lock = ruby_yaml("architecture.lock.yaml")
        relative = lock.get("machine_contracts", {}).get("terraform_provider_lock")
        if not isinstance(relative, str) or not relative.strip():
            raise RuntimeError("architecture.lock.yaml must register machine_contracts.terraform_provider_lock")

        contract = ruby_yaml(relative)
        if (
            contract.get("architecture_authority") != "architecture.lock.yaml"
            or contract.get("scope") != "platform/terraform"
            or contract.get("status") != "exact"
        ):
            raise RuntimeError("Terraform provider lock must inherit architecture.lock.yaml for platform/terraform")

        quality_authority = source_quality_adapter("terraform").get("validation", {}).get("provider_lock_authority")
        if quality_authority != "architecture.lock.yaml#machine_contracts.terraform_provider_lock":
            raise RuntimeError("Terraform quality validation must delegate provider resolution to the central lock contract")

        providers = contract.get("providers")
        if not isinstance(providers, dict) or not providers:
            raise RuntimeError("Terraform provider lock must declare at least one provider")

        for name, provider in providers.items():
            if not isinstance(name, str) or not name.strip() or not isinstance(provider, dict):
                raise RuntimeError("Terraform provider lock entries must be named mappings")
            for field in ("source", "version", "constraints"):
                value = provider.get(field)
                if not isinstance(value, str) or not value.strip():
                    raise RuntimeError(f"Terraform provider {name} must declare {field}")
            hashes = provider.get("hashes")
            if not isinstance(hashes, list) or not hashes or any(not isinstance(value, str) or not value for value in hashes):
                raise RuntimeError(f"Terraform provider {name} must declare non-empty hashes")
            if not any(value.startswith("h1:") for value in hashes) or not any(value.startswith("zh:") for value in hashes):
                raise RuntimeError(f"Terraform provider {name} must include both h1 and zh hashes")

        qualification = contract.get("qualification")
        if not isinstance(qualification, dict):
            raise RuntimeError("Terraform provider lock must declare qualification behavior")
        if qualification.get("canonical_lockfile_materialization") != "required":
            raise RuntimeError("Terraform qualification must materialize the canonical provider lock")
        if qualification.get("init_lockfile_mode") != "readonly":
            raise RuntimeError("Terraform qualification provider lock must be readonly")
        repository_context_paths = qualification.get("repository_context_paths")
        if (
            not isinstance(repository_context_paths, list)
            or not repository_context_paths
            or any(not isinstance(value, str) or not value.strip() for value in repository_context_paths)
        ):
            raise RuntimeError("Terraform qualification must declare non-empty repository_context_paths")

        _TERRAFORM_PROVIDER_LOCK = contract
    return copy.deepcopy(_TERRAFORM_PROVIDER_LOCK)


def write_terraform_provider_lock(path: Path, contract: dict | None = None) -> None:
    """Materialize Terraform's native lockfile from the canonical YAML authority."""
    provider_lock = contract or terraform_provider_lock_contract()
    lines = [
        "# Generated from architecture.lock.yaml#machine_contracts.terraform_provider_lock.",
        "# Do not edit this temporary projection.",
        "",
    ]
    for name in sorted(provider_lock["providers"]):
        provider = provider_lock["providers"][name]
        lines.extend(
            [
                f'provider {json.dumps(provider["source"])} {{',
                f'  version     = {json.dumps(provider["version"])}',
                f'  constraints = {json.dumps(provider["constraints"])}',
                "  hashes = [",
            ]
        )
        lines.extend(f"    {json.dumps(value)}," for value in provider["hashes"])
        lines.extend(["  ]", "}", ""])
    path.write_text("\n".join(lines), encoding="utf-8")


def terraform_provider_plugin_cache_dir(contract: dict | None = None) -> Path | None:
    """Return the persistent provider package cache; availability is an acceleration only."""
    provider_lock = contract or terraform_provider_lock_contract()
    cache = provider_lock["qualification"].get("provider_plugin_cache", {})
    env_name = str(cache.get("root_source", "ECOMMERCE_TOOL_HOME"))
    configured = os.environ.get(env_name, "").strip()
    base = Path(configured).expanduser() if configured else Path(str(cache.get("fallback_root", "~/.cache/ecommerce-1"))).expanduser()
    destination = base / str(cache.get("subdirectory", "terraform-provider-cache/v1"))
    try:
        destination.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        print(f"ADVISORY terraform provider cache unavailable: {exc}", file=sys.stderr)
        return None
    return destination


def pinned_versions() -> dict[str, str]:
    from capability_bootstrap import load_versions

    return load_versions()


def required_ansible_collections(requirements: Path | None = None) -> dict[str, str]:
    """Read Ansible collection versions from the central toolchain authority.

    An explicit requirements path is parsed only for focused mutation tests; the
    repository runtime never treats requirements.yml as an authority.
    """
    if requirements is None:
        from capability_bootstrap import load_toolchain_lock, validate_toolchain_projections

        contract = load_toolchain_lock()
        validate_toolchain_projections(contract)
        collections = contract.get("ansible_collections", {})
        if not isinstance(collections, dict) or not collections:
            raise RuntimeError("central toolchain lock must declare Ansible collections")
        return {str(name): str(version) for name, version in collections.items()}

    source = requirements
    result: dict[str, str] = {}
    name: str | None = None
    for raw in source.read_text(encoding="utf-8").splitlines():
        if match := re.match(r"\s*-\s+name:\s*([\w.]+)\s*$", raw):
            if name is not None:
                raise RuntimeError(f"missing version for Ansible collection {name} in {source}")
            name = match.group(1)
        elif match := re.match(r'\s+version:\s*["\']?([\w.-]+)["\']?\s*$', raw):
            if name is None or name in result:
                raise RuntimeError(f"invalid Ansible collection requirement in {source}")
            result[name] = match.group(1)
            name = None
    if name is not None or not result:
        raise RuntimeError(f"invalid Ansible collection requirements in {source}")
    return result


def resolved_ansible_collection_version(name: str, collections_root: Path = PROJECT_COLLECTIONS) -> str | None:
    """Return the version Ansible can resolve from its isolated project path."""
    namespace, collection = name.split(".", 1)
    manifest = collections_root / "ansible_collections" / namespace / collection / "MANIFEST.json"
    if not manifest.is_file():
        return None
    try:
        return str(json.loads(manifest.read_text(encoding="utf-8")).get("collection_info", {}).get("version"))
    except (OSError, json.JSONDecodeError):
        return None


def ansible_collections_check() -> int:
    rc = 0
    for name, expected in required_ansible_collections().items():
        actual = resolved_ansible_collection_version(name)
        if actual == expected:
            print(f"PASS ansible collection {name} {actual}")
        else:
            print(
                f"FAIL ansible collection {name}: expected {expected}, resolved {actual or 'missing'}", file=sys.stderr
            )
            rc = 1
    return rc


def ansible_collections_ready() -> bool:
    return all(
        resolved_ansible_collection_version(name) == expected
        for name, expected in required_ansible_collections().items()
    )


def reconcile_ansible_collections() -> None:
    """Reconcile the checkout-local pinned Galaxy collections only when missing or drifted."""
    if ansible_collections_ready():
        return
    require("ansible-playbook")
    require("ansible-galaxy")
    run(
        [
            "ansible-playbook",
            "-i",
            "localhost,",
            "-c",
            "local",
            "platform/ansible/developer.yml",
            "-e",
            f"repo_root={ROOT}",
            "--tags",
            "ansible_collections",
        ]
    )
    if not ansible_collections_ready():
        drift = []
        for name, expected in required_ansible_collections().items():
            actual = resolved_ansible_collection_version(name)
            if actual != expected:
                drift.append(f"{name}: expected {expected}, resolved {actual or 'missing'}")
        raise RuntimeError("project Ansible collection reconciliation incomplete: " + "; ".join(drift))
    print("PASS project-owned Ansible collections reconciled")


def developer_state_ready(tags: str) -> bool:
    """Fast-path: avoid Ansible startup when requested local state is already exact."""
    wanted = {tag.strip() for tag in tags.split(",") if tag.strip()}
    pins = pinned_versions()
    if "node" in wanted:
        node = shutil.which("node")
        corepack = shutil.which("corepack")
        if not node or not corepack:
            return False
        expected_node = pins.get("NODE_VERSION", "")
        got = run([node, "--version"], check=False, capture=True)
        if got.returncode or got.stdout.strip() != f"v{expected_node}":
            return False
    if "go" in wanted or "cgo" in wanted:
        managed_bin = managed_bin_dirs()[0]
        go = str(managed_bin / "go") if (managed_bin / "go").is_file() else None
        gofmt = str(managed_bin / "gofmt") if (managed_bin / "gofmt").is_file() else None
        if not go or not gofmt:
            return False
        got = run([go, "version"], check=False, capture=True)
        if got.returncode or f"go{pins.get('GO_VERSION', '')}" not in got.stdout:
            return False
    if "templ" in wanted:
        managed_bin = managed_bin_dirs()[0]
        templ = managed_bin / "templ"
        if not templ.is_file() or not os.access(templ, os.X_OK):
            return False
        got = run([str(templ), "version"], check=False, capture=True)
        if got.returncode or got.stdout.strip() != f"v{pins.get('TEMPL_VERSION', '')}" or got.stderr.strip():
            return False
    if "cgo" in wanted and not shutil.which("cc"):
        return False
    if "quality_tools" in wanted:
        for command, key in (("oxlint", "OXLINT_VERSION"), ("oxfmt", "OXFMT_VERSION"), ("ruff", "RUFF_VERSION")):
            executable = shutil.which(command)
            if not executable:
                return False
            got = run([executable, "--version"], check=False, capture=True)
            if got.returncode or pins.get(key, "") not in got.stdout:
                return False
    if "sqlc" in wanted:
        sqlc = shutil.which("sqlc")
        if not sqlc:
            return False
        got = run([sqlc, "version"], check=False, capture=True)
        expected = pins.get("SQLC_VERSION", "")
        if got.returncode or (expected not in got.stdout):
            return False
    if "docker" in wanted:
        docker = shutil.which("docker")
        if not docker or run([docker, "info"], check=False, capture=True).returncode != 0:
            return False
    return True


def canonical_services() -> list[str]:
    return [str(x) for x in ruby_yaml("architecture.lock.yaml").get("business", {}).get("services", [])]


def run_ruby_tests(paths: list[str]) -> None:
    require("ruby")
    for path in paths:
        run(["ruby", "-Itest", path])


def runtime_efficiency_check() -> int:
    require("ruby")
    run(["ruby", "scripts/validate-runtime-efficiency.rb"])
    run_ruby_tests(["tests/runtime_efficiency_test.rb", "tests/resource_sizing_test.rb"])
    print("PASS runtime efficiency checks completed")
    return 0


def governance() -> int:
    repository_authority_check()
    run([sys.executable, "scripts/architecture_authority.py"])
    run([sys.executable, "-m", "unittest", "discover", "-s", "tests", "-p", "test_architecture_authority.py"])
    require("ruby")
    for validator in (
        "scripts/validate-architecture.rb",
        "scripts/validate-architecture-boundaries.rb",
        "scripts/validate-service-policy-chain.rb",
        "scripts/validate-service-mesh-policy.rb",
        "scripts/validate-contract-consistency.rb",
        "scripts/validate-observability.rb",
    ):
        run(["ruby", validator])
    run_ruby_tests(
        [
            "tests/architecture_validator_test.rb",
            "tests/observability_topology_test.rb",
            "tests/ci_authority_test.rb",
            "tests/ci_affected_test.rb",
        ]
    )
    if documentation_policy():
        return 1
    print("PASS governance checks completed")
    return 0


def bundle_openapi_with_common(spec: Path, common_spec: Path) -> dict:
    """Return a single-document OpenAPI spec with canonical common components merged.

    oapi-codegen treats local multi-file refs as external package refs and therefore
    requires import-mapping. ecommerce-1 deliberately keeps common REST components
    in a separate canonical document, but generated service bindings stay inside the
    service package. Bundling the canonical common components avoids fake Go package
    boundaries while preserving the repository's split source contracts.

    Only refs to the registry-declared common document are accepted here. Any other
    external ref fails closed so code generation cannot silently pull in an
    undeclared local/remote dependency.
    """
    service_doc = copy.deepcopy(ruby_yaml(str(spec)))
    common_doc = copy.deepcopy(ruby_yaml(str(common_spec)))
    common_components = common_doc.get("components") or {}
    if not isinstance(common_components, dict):
        raise RuntimeError(f"common OpenAPI components must be a mapping: {common_spec}")

    spec_abs = spec.resolve()
    common_abs = common_spec.resolve()
    service_components = service_doc.setdefault("components", {})
    if not isinstance(service_components, dict):
        raise RuntimeError(f"service OpenAPI components must be a mapping: {spec}")

    def resolve_external(ref: str) -> tuple[Path, str]:
        path_part, sep, fragment = ref.partition("#")
        if not sep or not fragment.startswith("/components/"):
            raise RuntimeError(f"unsupported external OpenAPI reference {ref!r} in {spec}")
        if "://" in path_part or path_part.startswith("//"):
            raise RuntimeError(f"remote OpenAPI reference forbidden during generation: {ref!r}")
        target = (spec_abs.parent / path_part).resolve()
        if target != common_abs:
            raise RuntimeError(
                f"external OpenAPI reference {ref!r} does not target canonical common components {common_spec}"
            )
        return target, fragment

    def rewrite_refs(node):
        if isinstance(node, dict):
            ref = node.get("$ref")
            if isinstance(ref, str) and not ref.startswith("#"):
                _, fragment = resolve_external(ref)
                node["$ref"] = f"#{fragment}"
            for value in node.values():
                rewrite_refs(value)
        elif isinstance(node, list):
            for value in node:
                rewrite_refs(value)

    # Merge canonical common components first. A service may intentionally expose a
    # same-name alias such as bearerAuth -> common.v1.yaml#/components/...; replace
    # that alias with the canonical definition. Real conflicting definitions fail.
    rel_common = Path(os.path.relpath(common_abs, spec_abs.parent)).as_posix()
    for group, common_values in common_components.items():
        if not isinstance(common_values, dict):
            raise RuntimeError(f"common component group {group!r} must be a mapping")
        target_group = service_components.setdefault(group, {})
        if not isinstance(target_group, dict):
            raise RuntimeError(f"service component group {group!r} must be a mapping")
        for key, common_value in common_values.items():
            current = target_group.get(key)
            expected_refs = {
                f"{rel_common}#/components/{group}/{key}",
                f"./{rel_common}#/components/{group}/{key}",
            }
            if current is None:
                target_group[key] = copy.deepcopy(common_value)
            elif isinstance(current, dict) and set(current) == {"$ref"} and current.get("$ref") in expected_refs:
                target_group[key] = copy.deepcopy(common_value)
            elif current != common_value:
                raise RuntimeError(f"service/common OpenAPI component collision at components/{group}/{key}")

    rewrite_refs(service_doc)

    # Generation must now be self-contained. Keep internal refs intact so named
    # service schemas retain stable generated Go/TypeScript type names.
    leftovers: list[str] = []

    def collect_external(node):
        if isinstance(node, dict):
            ref = node.get("$ref")
            if isinstance(ref, str) and not ref.startswith("#"):
                leftovers.append(ref)
            for value in node.values():
                collect_external(value)
        elif isinstance(node, list):
            for value in node:
                collect_external(value)

    collect_external(service_doc)
    if leftovers:
        raise RuntimeError(f"bundled OpenAPI still contains external refs: {sorted(set(leftovers))}")
    return service_doc


def api_generate(target: str = "go", service: str = "", check: bool = False) -> int:
    if target != "go":
        return fail("api-generate target must be go; Node.js application bindings are forbidden")
    registry = ruby_yaml("config/contracts/public-api-contracts.yaml")
    contracts = registry.get("contracts", {})
    common_entry = registry.get("common_components")
    if not common_entry:
        return fail("api-generate registry must declare common_components")
    common_spec = ROOT / common_entry
    if not common_spec.is_file():
        return fail(f"api-generate missing common contract: {common_spec.relative_to(ROOT)}")
    selected = [(name, entry) for name, entry in contracts.items() if not service or name == service]
    if not selected:
        return fail(f"api-generate no registered service matched {service!r}")
    for name, entry in selected:
        spec = ROOT / entry["path"]
        if not spec.is_file():
            return fail(f"api-generate missing contract: {spec.relative_to(ROOT)}")
        bundled_doc = bundle_openapi_with_common(spec, common_spec)
        with tempfile.TemporaryDirectory(prefix=f"ecommerce-{name}-openapi-") as temp_dir:
            bundled_spec = Path(temp_dir) / f"{name}.bundled.json"
            bundled_spec.write_text(json.dumps(bundled_doc, indent=2, sort_keys=True) + "\n", encoding="utf-8")
            if target == "go":
                require("oapi-codegen")
                require("gofmt")
                module = ROOT / "services" / name
                out_dir = module / "api" / "generated"
                if not module.is_dir():
                    print(f"SKIP api-generate go {name}: service not implemented")
                else:
                    if not (module / "go.mod").is_file():
                        return fail(f"api-generate implemented service lacks go.mod: services/{name}/go.mod")
                    generated = out_dir / "openapi.gen.go"
                    candidate = Path(temp_dir) / f"{name}.openapi.gen.go" if check else generated
                    if not check:
                        out_dir.mkdir(parents=True, exist_ok=True)
                    config_path = Path(temp_dir) / f"{name}.oapi-codegen.yaml"
                    config_path.write_text(
                        f"package: generated\noutput: {candidate}\ngenerate:\n  models: true\n  std-http-server: true\n  strict-server: true\n",
                        encoding="utf-8",
                    )
                    # Run from the owning Go module so oapi-codegen can resolve the
                    # module/runtime context instead of warning from repository root.
                    run(["oapi-codegen", "--config", str(config_path), str(bundled_spec)], cwd=module)
                    run(["gofmt", "-w", str(candidate)], cwd=module)
                    if check and (not generated.is_file() or candidate.read_bytes() != generated.read_bytes()):
                        return fail(f"generated API binding is stale: {generated.relative_to(ROOT)}")
    print(f"PASS generated API bindings target={target}")
    return 0


def api_compat(base: str, head: str) -> int:
    require("oasdiff")
    args = ["diff", "--name-only", "--diff-filter=ACMRTUXB", base]
    if head != "WORKTREE":
        args.append(head)
    args += ["--", "contracts/openapi", "config/contracts/public-api-contracts.yaml"]
    changed = [x for x in git(*args).splitlines() if x]
    if not changed:
        print("SKIP OpenAPI compatibility: no API contract changes")
        return 0
    registry = ruby_yaml("config/contracts/public-api-contracts.yaml")
    common = registry.get("common_components")
    specs = [entry["path"] for entry in registry.get("contracts", {}).values()]
    with (
        tempfile.TemporaryDirectory(prefix="ecommerce-oas-old-") as old_s,
        tempfile.TemporaryDirectory(prefix="ecommerce-oas-new-") as new_s,
    ):
        old = Path(old_s)
        new = Path(new_s)
        for tree, ref in ((old, base), (new, head)):
            if ref == "WORKTREE":
                shutil.copytree(ROOT / "contracts" / "openapi", tree / "contracts" / "openapi", dirs_exist_ok=True)
                (tree / "config" / "contracts").mkdir(parents=True, exist_ok=True)
                shutil.copy2(
                    ROOT / "config" / "contracts" / "public-api-contracts.yaml",
                    tree / "config" / "contracts" / "public-api-contracts.yaml",
                )
            else:
                # git archive is binary; stream it directly to tar.
                proc1 = subprocess.Popen(
                    ["git", "archive", ref, "contracts/openapi", "config/contracts/public-api-contracts.yaml"],
                    cwd=ROOT,
                    stdout=subprocess.PIPE,
                )
                proc2 = subprocess.run(["tar", "-x", "-C", str(tree)], stdin=proc1.stdout)
                if proc1.stdout:
                    proc1.stdout.close()
                rc = proc1.wait()
                if rc or proc2.returncode:
                    raise RuntimeError(f"git archive failed for {ref}")
        common_changed = bool(common and common in changed)
        for spec in specs:
            if not common_changed and spec not in changed:
                continue
            if not (old / spec).is_file():
                print(f"SKIP OpenAPI compatibility: {spec} is new relative to {base}")
                continue
            print(f"CHECK OpenAPI compatibility: {spec}")
            run(["oasdiff", "breaking", "--fail-on", "ERR", str(old / spec), str(new / spec)])
    print("PASS OpenAPI compatibility checks completed")
    return 0


def contracts(base: str = "", head: str = "WORKTREE", generate: bool = False) -> int:
    require("ruby")
    run(["ruby", "scripts/validate-openapi.rb"])
    run(["ruby", "scripts/validate-contract-consistency.rb"])
    run_ruby_tests(["tests/openapi_validator_test.rb", "tests/contract_consistency_test.rb"])
    contract_changed = False
    if base:
        args = ["diff", "--name-only", "--diff-filter=ACMRTUXB", base]
        if head != "WORKTREE":
            args.append(head)
        args += ["--", "contracts/openapi", "config/contracts/public-api-contracts.yaml"]
        contract_changed = bool(git(*args).strip())
        api_compat(base, head)
    if generate or contract_changed:
        result = api_generate("go", check=True)
        if result:
            return result
    print("PASS OpenAPI and cross-registry contract checks completed")
    return 0


def repository_shell_paths(root: Path = ROOT) -> list[str]:
    """Return Shell files that exist in the effective Git worktree.

    `git ls-files` alone reports paths that are still present in the index even when
    they have been deleted but not staged yet. The migration gate runs against
    WORKTREE before commit, so those intentional deletions must not be false
    positives. Include untracked, non-ignored files so newly introduced Shell
    automation still fails closed.
    """
    candidates = output(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard", "--", "*.sh"],
        cwd=root,
    ).splitlines()
    return sorted(path for path in candidates if path and (root / path).is_file())


def automation_policy() -> int:
    # Shell source is forbidden repository-wide after the Ansible-first migration.
    shell_files = repository_shell_paths()
    if shell_files:
        print(
            "FAIL shell automation policy: repository *.sh files are forbidden after Ansible-first migration",
            file=sys.stderr,
        )
        for path in shell_files:
            print(f"  {path}", file=sys.stderr)
        return 1
    bad = []
    for path in (ROOT / "platform" / "tekton").rglob("*.yaml"):
        text = path.read_text(encoding="utf-8", errors="replace")
        if re.search(r"scripts/[^\s'\"]+\.sh\b", text) or "#!/bin/sh" in text or "#!/usr/bin/env bash" in text:
            bad.append(path)
    if bad:
        print("FAIL automation policy: Tekton must invoke native commands/Make, not shell wrappers", file=sys.stderr)
        for path in bad:
            print(f"  {path.relative_to(ROOT)}", file=sys.stderr)
        return 1
    build = ROOT / "BUILD.bazel"
    if build.is_file() and "sh_binary(" in build.read_text(encoding="utf-8"):
        return fail("automation policy: Bazel sh_binary is forbidden; use py_binary/native targets", 1)
    print("PASS automation policy: zero repository *.sh files and no Tekton shell wrappers")
    return 0


def documentation_policy() -> int:
    """Reject active documentation that contradicts the canonical automation model."""
    rules = {
        "AGENTS.md": [r"portable POSIX `sh`", r"repository shell helpers"],
        "README.md": [r"scripts/ci-\*\.sh"],
        "docs/project/CODEX_HANDOFFS.md": [r"shared POSIX `sh` helpers", r"shared repository scripts factored"],
        "docs/api/README.md": [r"bootstrap CI Woodpecker"],
    }
    failures: list[str] = []
    for relative, patterns in rules.items():
        text = (ROOT / relative).read_text(encoding="utf-8")
        for pattern in patterns:
            if re.search(pattern, text, flags=re.IGNORECASE):
                failures.append(f"{relative}: {pattern}")
    if failures:
        print("FAIL documentation policy: active legacy automation references found", file=sys.stderr)
        print("\n".join(f"  {item}" for item in failures), file=sys.stderr)
        return 1
    print("PASS documentation policy: active automation references are canonical")
    return 0


def frontend(action: str, scope: str = "") -> int:
    # Accept both `repoctl frontend storefront` and the compatibility form
    # `repoctl frontend check storefront` used by existing Tekton tasks.
    if not scope:
        scope, action = action, "check"
    if action not in {"check", "lint", "test", "build", "generate", "run"} or scope not in {"all", "storefront", "admin"}:
        return fail("frontend usage: frontend <storefront|admin|all>")
    ensure_developer("go,cgo,templ")
    managed_bin = managed_bin_dirs()[0]
    env = dict(os.environ, PATH=f"{managed_bin}:{os.environ.get('PATH', '')}")
    # A version manager may export a GOROOT for a different system Go. The
    # repository-managed binary must discover and execute its own toolchain.
    env.pop("GOROOT", None)
    env.pop("GOTOOLDIR", None)
    go = managed_bin / "go"
    gofmt = managed_bin / "gofmt"
    templ = managed_bin / "templ"
    if not go.is_file() or not gofmt.is_file() or not templ.is_file():
        raise RuntimeError("validated managed Go/templ provider is unavailable")
    targets = ["storefront", "admin"] if scope == "all" else [scope]
    frontend_root = ROOT / "frontend"
    templ_version = pinned_versions().get("TEMPL_VERSION")
    if not templ_version:
        raise RuntimeError("TEMPL_VERSION is missing from central toolchain lock")
    if action == "run":
        if scope == "all":
            return site()
        return run([str(go), "run", f"./apps/{scope}"], cwd=frontend_root, env=env, check=False).returncode

    if action == "generate":
        if scope != "all":
            return fail("frontend generate is repository-wide; scope must be all")
        run([str(templ), "generate"], cwd=frontend_root, env=env)
        print("PASS frontend generated from central templ version")
        return 0

    if action in {"check", "lint"}:
        files = sorted(str(path) for path in frontend_root.rglob("*.go"))
        formatted = run([str(gofmt), "-l", *files], capture=True, env=env)
        advisory_output_check("frontend gofmt", formatted.stdout or "")
        forbidden_frontend_artifacts()
        if action == "check":
            with tempfile.TemporaryDirectory(prefix="ecommerce-frontend-templ-") as temp_dir:
                generated_root = Path(temp_dir) / "frontend"
                shutil.copytree(frontend_root, generated_root)
                run([str(templ), "generate"], cwd=generated_root, env=env)
                committed = sorted(frontend_root.rglob("*_templ.go"))
                generated = sorted(generated_root.rglob("*_templ.go"))
                relative_committed = [path.relative_to(frontend_root) for path in committed]
                relative_generated = [path.relative_to(generated_root) for path in generated]
                if relative_committed != relative_generated:
                    return fail("frontend templ generated file set is stale")
                for relative in relative_committed:
                    if (frontend_root / relative).read_bytes() != (generated_root / relative).read_bytes():
                        return fail(f"frontend templ generated code is stale: {relative}")
        if action == "lint":
            run([str(go), "vet", "./..."], cwd=frontend_root, env=env)
    if action in {"check", "test"}:
        env = dict(env, CGO_ENABLED="1")
        # One module-wide invocation runs shared package tests exactly once as well as
        # the independently deployable application packages.
        run([str(go), "test", "-race", "./..."], cwd=frontend_root, env=env)
    if action in {"check", "build"}:
        with tempfile.TemporaryDirectory(prefix="ecommerce-frontend-build-") as output_dir:
            for target in targets:
                run(
                    [str(go), "build", "-o", str(Path(output_dir) / target), f"./apps/{target}"],
                    cwd=frontend_root,
                    env=env,
                )
    if action == "check":
        run([str(go), "vet", "./..."], cwd=frontend_root, env=env)
    print(f"PASS frontend {scope} {action} checks completed")
    return 0


def site() -> int:
    """Run both independently deployable Go frontends until interrupted."""
    ensure_developer("go")
    env = dict(os.environ, PATH=f"{os.pathsep.join(str(path) for path in managed_bin_dirs())}{os.pathsep}{os.environ.get('PATH', '')}")
    with tempfile.TemporaryDirectory(prefix="ecommerce-site-") as output_dir:
        binaries = [Path(output_dir) / "storefront", Path(output_dir) / "admin"]
        for target, binary in zip(("storefront", "admin"), binaries, strict=True):
            run(["go", "build", "-o", str(binary), f"./apps/{target}"], cwd=ROOT / "frontend", env=env)
        addresses = (
            os.environ.get("STOREFRONT_HTTP_ADDR", ":8080"),
            os.environ.get("ADMIN_HTTP_ADDR", ":8081"),
        )
        processes = [
            subprocess.Popen(
                [str(binary)],
                cwd=ROOT / "frontend",
                env=dict(env, HTTP_ADDR=address),
                start_new_session=(os.name != "nt"),
                creationflags=getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0) if os.name == "nt" else 0,
            )
            for binary, address in zip(binaries, addresses, strict=True)
        ]
        previous_handlers = {}

        def interrupt(_signum, _frame):
            raise KeyboardInterrupt

        for signum in (signal.SIGINT, signal.SIGTERM):
            previous_handlers[signum] = signal.signal(signum, interrupt)
        try:
            while all(process.poll() is None for process in processes):
                time.sleep(0.2)
        except KeyboardInterrupt:
            pass
        finally:
            intentionally_stopped: set[int] = set()
            for process in processes:
                if process.poll() is not None:
                    continue
                intentionally_stopped.add(id(process))
                if os.name == "nt":
                    subprocess.run(
                        [str(Path(os.environ.get("SystemRoot", r"C:\\Windows")) / "System32/taskkill.exe"), "/PID", str(process.pid), "/T", "/F"],
                        check=False,
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                    )
                else:
                    try:
                        os.killpg(process.pid, signal.SIGTERM)
                    except ProcessLookupError:
                        pass
            for process in processes:
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    if os.name != "nt":
                        try:
                            os.killpg(process.pid, signal.SIGKILL)
                        except ProcessLookupError:
                            pass
                    process.wait()
            for signum, handler in previous_handlers.items():
                signal.signal(signum, handler)
        failed = [
            process.returncode
            for process in processes
            if id(process) not in intentionally_stopped and process.returncode not in (0, None)
        ]
        return failed[0] if failed else 0


def reconcile(tags: str, target_repo_root: str = "") -> int:
    selected = ",".join(part.strip() for part in tags.split(",") if part.strip())
    if not selected:
        return fail("reconcile requires at least one Ansible tag")
    require("ansible-playbook")
    repo_root = Path(target_repo_root).expanduser().resolve() if target_repo_root else ROOT
    run(
        [
            "ansible-playbook",
            "-i",
            "localhost,",
            "-c",
            "local",
            "platform/ansible/developer.yml",
            "-e",
            f"repo_root={repo_root}",
            "--tags",
            selected,
        ]
    )
    print(f"PASS reconcile tags={selected}")
    return 0


def bazel_verify(base: str, head: str) -> int:
    require("bazel")
    return run(
        ["bazel", "run", "//:repoctl", "--", "verify-change", "--base", base, "--head", head],
        check=False,
    ).returncode


def resource_candidate(evidence: str) -> int:
    if not evidence:
        return fail("resource-candidate requires EVIDENCE")
    require("ruby")
    return run(["ruby", "scripts/resource-sizing.rb", evidence], check=False).returncode


def tekton_proof(runtime_config: str, base_sha: str, parent_sha: str, head_sha: str) -> int:
    missing = [
        name
        for name, value in (
            ("RUNTIME_CONFIG", runtime_config),
            ("BASE_SHA", base_sha),
            ("PARENT_SHA", parent_sha),
            ("HEAD_SHA", head_sha),
        )
        if not value
    ]
    if missing:
        return fail("tekton-proof missing required values: " + ", ".join(missing))
    require("ansible-playbook")
    run(
        [
            "ansible-playbook",
            "-i",
            "localhost,",
            "-c",
            "local",
            "platform/ansible/tekton-proof.yml",
            "-e",
            f"repo_root={ROOT}",
            "-e",
            f"tekton_runtime_config={runtime_config}",
            "-e",
            f"proof_base_sha={base_sha}",
            "-e",
            f"proof_parent_sha={parent_sha}",
            "-e",
            f"proof_head_sha={head_sha}",
        ]
    )
    return 0


def product_run() -> int:
    ensure_developer("go")
    managed_bin = managed_bin_dirs()[0]
    go = managed_bin / "go"
    if not go.is_file():
        raise RuntimeError("validated managed Go provider is unavailable")
    env = dict(os.environ, PATH=f"{managed_bin}{os.pathsep}{os.environ.get('PATH', '')}")
    env.pop("GOROOT", None)
    env.pop("GOTOOLDIR", None)
    return run([str(go), "run", "./services/product/cmd/product-api"], env=env, check=False).returncode


def product_benchmark() -> int:
    ensure_developer("go")
    managed_bin = managed_bin_dirs()[0]
    go = managed_bin / "go"
    if not go.is_file():
        raise RuntimeError("validated managed Go provider is unavailable")
    env = dict(os.environ, PATH=f"{managed_bin}{os.pathsep}{os.environ.get('PATH', '')}")
    env.pop("GOROOT", None)
    env.pop("GOTOOLDIR", None)
    return run(
        [
            str(go),
            "test",
            "-run",
            "^$",
            "-bench",
            "^BenchmarkListProductsEmpty$",
            "-benchmem",
            "./internal/transport/rest",
        ],
        cwd=ROOT / "services/product",
        env=env,
        check=False,
    ).returncode


def forbidden_frontend_artifacts() -> None:
    forbidden_names = {
        "package.json",
        "pnpm-lock.yaml",
        "package-lock.json",
        "yarn.lock",
        ".node-version",
        ".nvmrc",
        "next.config.js",
        "next.config.ts",
        "playwright.config.ts",
        "turbo.json",
        "pnpm-workspace.yaml",
    }
    forbidden_suffixes = {".ts", ".tsx"}
    paths = set(git("ls-files").splitlines()) | set(git("ls-files", "--others", "--exclude-standard").splitlines())
    violations = sorted(
        path for path in paths if Path(path).name in forbidden_names or Path(path).suffix in forbidden_suffixes
    )
    if violations:
        raise RuntimeError("forbidden Node.js frontend artifacts: " + ", ".join(violations))


def ensure_developer(tags: str) -> None:
    if developer_state_ready(tags):
        return
    require("ansible-playbook")
    run(
        [
            "ansible-playbook",
            "-i",
            "localhost,",
            "-c",
            "local",
            "platform/ansible/developer.yml",
            "-e",
            f"repo_root={ROOT}",
            "--tags",
            tags,
        ]
    )
    if not developer_state_ready(tags):
        raise RuntimeError(f"developer state reconciliation did not satisfy tags: {tags}")


def service_check(service: str) -> int:
    if not re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", service or ""):
        return fail("SERVICE must be a canonical lowercase service name")
    if service not in canonical_services():
        return fail(f"service is not canonical: {service}")
    module = ROOT / "services" / service
    if not (module / "go.mod").is_file():
        return fail(f"service module does not exist: services/{service}/go.mod")
    capabilities = ["go", "cgo"]
    if (module / "sqlc.yaml").is_file():
        capabilities.append("sqlc")
    selected_tests = list(module.rglob("*_test.go"))
    needs_containers = any("testcontainers" in path.read_text(encoding="utf-8") for path in selected_tests)
    ensure_developer(",".join(capabilities))
    env = os.environ.copy()
    env["PATH"] = f"{os.pathsep.join(str(path) for path in managed_bin_dirs())}{os.pathsep}{env.get('PATH', '')}"
    env.pop("GOROOT", None)
    env.pop("GOTOOLDIR", None)
    env["CGO_ENABLED"] = "1"
    if (module / "sqlc.yaml").is_file():
        cfg = ruby_yaml(str(module / "sqlc.yaml"))
        out_dir = cfg["sql"][0]["gen"]["go"]["out"]
        with tempfile.TemporaryDirectory(prefix=f"{service}-sqlc-") as temp:
            tmp = Path(temp)
            shutil.copytree(module, tmp / service, dirs_exist_ok=True)
            run(["sqlc", "generate"], cwd=tmp / service, env=env)
            run(["sqlc", "vet"], cwd=tmp / service, env=env)
            diff = run(["diff", "-ru", str(module / out_dir), str(tmp / service / out_dir)], check=False, capture=True)
            if diff.returncode:
                print(diff.stdout)
                return fail(f"{service} sqlc generated code is stale")
    require("gofmt")
    go_files = [str(p) for p in module.rglob("*.go") if "vendor" not in p.parts]
    if go_files:
        p = run(["gofmt", "-l", *go_files], capture=True)
        if p.stdout.strip():
            print(p.stdout, file=sys.stderr)
            return fail(f"gofmt required for {service}", 1)
    run(["go", "test", "-race", "./..."], cwd=module, env=env)
    run(["go", "vet", "./..."], cwd=module, env=env)
    run(["go", "build", "./..."], cwd=module, env=env)
    if needs_containers:
        docker = shutil.which("docker")
        forwarding = run(["sysctl", "-n", "net.ipv4.ip_forward"], check=False, capture=True)
        docker_ready = bool(docker) and run([docker, "info"], check=False, capture=True).returncode == 0
        if not docker_ready or forwarding.returncode or forwarding.stdout.strip() != "1":
            return fail(
                "PLATFORM NOT CAPABLE: container integration requires Docker user/daemon access "
                "and net.ipv4.ip_forward=1",
                2,
            )
    if (module / "internal" / "infrastructure" / "postgres").is_dir():
        run(
            ["go", "test", "-race", "-tags=integration", "./internal/infrastructure/postgres", "-count=1"],
            cwd=module,
            env=env,
        )
    print(f"PASS {service} service checks completed")
    return 0


def security() -> int:
    policy = security_scan_policy()
    scanner = policy.get("scanner", {})
    command = str(scanner.get("name", "gitleaks"))
    require(command)

    execution = policy.get("execution", {})
    with tempfile.TemporaryDirectory(prefix="ecommerce-security-policy-") as policy_dir:
        config = Path(policy_dir) / "gitleaks.toml"
        write_gitleaks_policy_config(config, policy)
        flags = ["--config", str(config)]
        if execution.get("redact") is True:
            flags.append("--redact")
        if execution.get("no_banner") is True:
            flags.append("--no-banner")

        if os.environ.get("HEAD", "").strip() == "WORKTREE":
            tree_sha = worktree_tree_sha()
            with tempfile.TemporaryDirectory(prefix="ecommerce-gitleaks-worktree-") as temp_dir:
                temp_root = Path(temp_dir)
                archive = temp_root / "tree.tar"
                scan_root = temp_root / "tree"
                scan_root.mkdir()
                run(["git", "archive", "--format=tar", "--output", str(archive), tree_sha])
                shutil.unpack_archive(str(archive), str(scan_root), "tar")
                run([command, "dir", *flags, str(scan_root)])
        elif run(["git", "rev-parse", "--verify", "HEAD"], check=False, capture=True).returncode == 0:
            run([command, "git", *flags, "."])
        else:
            run([command, "dir", *flags, "."])

    print("PASS secret scan completed")
    return 0

def terraform_check() -> int:
    terraform_root = ROOT / "platform" / "terraform"
    tf_files = [p for p in terraform_root.rglob("*.tf") if ".terraform" not in p.parts]
    if not tf_files:
        print("SKIP terraform: no Terraform files found")
        return 0

    policy = source_quality_adapter("terraform")
    formatter = policy["formatter"]
    provider_lock = terraform_provider_lock_contract()
    qualification = provider_lock["qualification"]

    tool = next(
        (shutil.which(name) for name in formatter["executable_preference"] if shutil.which(name)),
        None,
    )
    if not tool:
        return fail("Terraform sources exist but no centrally approved Terraform/OpenTofu executable is installed")

    advisory_exit_check(
        "terraform fmt",
        [tool, *formatter["args"]],
        drift_exit_codes=formatter["drift_exit_codes"],
    )

    provider_cache = terraform_provider_plugin_cache_dir(provider_lock)
    env = os.environ.copy()
    if provider_cache is not None:
        env["TF_PLUGIN_CACHE_DIR"] = str(provider_cache)

    directories = sorted({p.parent for p in tf_files})
    with tempfile.TemporaryDirectory(prefix="ecommerce-terraform-validation-") as temp_dir:
        temp_repo_root = Path(temp_dir) / "repository"
        temp_root = temp_repo_root / "platform" / "terraform"
        temp_root.parent.mkdir(parents=True, exist_ok=True)
        shutil.copytree(
            terraform_root,
            temp_root,
            ignore=shutil.ignore_patterns(".terraform", ".terraform.lock.hcl"),
        )
        for relative_context in qualification.get("repository_context_paths", []):
            source = ROOT / str(relative_context)
            destination = temp_repo_root / str(relative_context)
            if not source.exists():
                raise RuntimeError(f"Terraform qualification repository context is missing: {relative_context}")
            destination.parent.mkdir(parents=True, exist_ok=True)
            if source.is_dir():
                shutil.copytree(source, destination)
            else:
                shutil.copy2(source, destination)

        for directory in directories:
            relative = directory.relative_to(terraform_root)
            validation_dir = temp_root / relative
            write_terraform_provider_lock(validation_dir / ".terraform.lock.hcl", provider_lock)
            print(f"CHECK terraform: {relative}")
            run([tool, *qualification["init_args"]], cwd=validation_dir, env=env)
            run([tool, *qualification["validate_args"]], cwd=validation_dir, env=env)

    providers = ", ".join(
        f"{name}={provider['version']}"
        for name, provider in sorted(provider_lock["providers"].items())
    )
    print(f"PASS terraform provider lock {providers}")
    print("PASS terraform checks completed")
    return 0
def ansible_check() -> int:
    reconcile_ansible_collections()
    require("ansible-lint")
    files = sorted(str(p.relative_to(ROOT)) for p in (ROOT / "platform" / "ansible").rglob("*.yml"))
    files += sorted(str(p.relative_to(ROOT)) for p in (ROOT / "platform" / "ansible").rglob("*.yaml"))
    if not files:
        print("SKIP ansible: no Ansible files found")
        return 0

    lint_policy = source_quality_adapter("ansible")["lint"]
    advisory_rules = [str(rule) for rule in lint_policy["advisory_rules"]]
    with tempfile.TemporaryDirectory(prefix="ecommerce-ansible-lint-policy-") as temp_dir:
        config = Path(temp_dir) / "ansible-lint.yml"
        config.write_text(
            "---\nwarn_list:\n"
            + "".join(f"  - {rule}\n" for rule in advisory_rules),
            encoding="utf-8",
        )
        run(["ansible-lint", "--config-file", str(config), *files])

    run(
        [
            "ansible-playbook",
            "-i",
            "localhost,",
            "-c",
            "local",
            "platform/ansible/developer.yml",
            "--syntax-check",
            "-e",
            f"repo_root={ROOT}",
        ]
    )
    if ansible_collections_check():
        return 1
    print("PASS ansible checks completed")
    return 0


def _git_neutral_test_env() -> dict[str, str]:
    """Remove repository-local Git variables before tests create nested repositories."""
    env = os.environ.copy()
    for name in output(["git", "rev-parse", "--local-env-vars"]).splitlines():
        if name:
            env.pop(name, None)
    return env


def system_check() -> int:
    test_env = _git_neutral_test_env()
    tests = sorted(str(p.relative_to(ROOT)) for p in (ROOT / "tests").glob("*_test.rb"))
    run_ruby_tests(tests)
    for suite in [ROOT / "tests", ROOT / "tests" / "delivery", ROOT / "tests" / "context"]:
        if suite.is_dir() and any(suite.glob("test_*.py")):
            run(
                [sys.executable, "-m", "unittest", "discover", "-s", str(suite.relative_to(ROOT)), "-p", "test_*.py"],
                env=test_env,
            )
    print("PASS cross-system repository checks completed")
    return 0


def write_ruff_policy_config(path: Path) -> None:
    """Materialize Ruff's adapter config from the central source-quality contract."""
    config = source_quality_adapter("python")["configuration"]
    target_version = str(config["target_version"])
    line_length = int(config["line_length"])
    extend_exclude = [str(item) for item in config["extend_exclude"]]
    lint_select = [str(item) for item in config["lint_select"]]
    path.write_text(
        f'target-version = "{target_version}"\n'
        f"line-length = {line_length}\n"
        + "extend-exclude = "
        + json.dumps(extend_exclude)
        + "\n\n[lint]\nselect = "
        + json.dumps(lint_select)
        + "\n",
        encoding="utf-8",
    )


def format_check() -> int:
    """Run repository-wide non-mutating formatter diagnostics from the central policy."""
    python_files = sorted(str(path) for tree in (ROOT / "scripts", ROOT / "tests") for path in tree.rglob("*.py"))
    if python_files:
        require("ruff")
        formatter = source_quality_adapter("python")["formatter"]
        with tempfile.TemporaryDirectory(prefix="ecommerce-ruff-policy-") as temp_dir:
            config = Path(temp_dir) / "ruff.toml"
            write_ruff_policy_config(config)
            advisory_exit_check(
                "ruff format",
                [formatter["command"], *formatter["args"], "--config", str(config), *python_files],
                drift_exit_codes=formatter["drift_exit_codes"],
            )

    go_files = sorted(
        str(path)
        for tree in (ROOT / "services", ROOT / "frontend")
        if tree.is_dir()
        for path in tree.rglob("*.go")
        if "vendor" not in path.parts
    )
    if go_files:
        require("gofmt")
        go_policy = source_quality_adapter("go")["formatter"]
        result = run([go_policy["command"], *go_policy["args"], *go_files], capture=True)
        advisory_output_check("gofmt", result.stdout or "")

    tf_files = [p for p in ROOT.rglob("*.tf") if ".terraform" not in p.parts]
    if tf_files:
        terraform_policy = source_quality_adapter("terraform")["formatter"]
        tool = next(
            (shutil.which(name) for name in terraform_policy["executable_preference"] if shutil.which(name)),
            None,
        )
        if not tool:
            return fail("Terraform sources exist but no centrally approved Terraform/OpenTofu executable is installed")
        advisory_exit_check(
            "terraform fmt",
            [tool, *terraform_policy["args"]],
            drift_exit_codes=terraform_policy["drift_exit_codes"],
        )

    print("PASS source format diagnostics completed")
    return 0


def lint_all() -> int:
    if automation_policy():
        return 1
    go_files = [str(p) for p in (ROOT / "services").rglob("*.go") if "vendor" not in p.parts]
    if go_files:
        require("gofmt")
        p = run(["gofmt", "-l", *go_files], capture=True)
        advisory_output_check("service gofmt", p.stdout or "")
    python_files = sorted(str(path) for tree in (ROOT / "scripts", ROOT / "tests") for path in tree.rglob("*.py"))
    if python_files:
        require("ruff")
        python_policy = source_quality_adapter("python")
        formatter = python_policy["formatter"]
        lint_policy = python_policy["lint"]
        with tempfile.TemporaryDirectory(prefix="ecommerce-ruff-policy-") as temp_dir:
            config = Path(temp_dir) / "ruff.toml"
            write_ruff_policy_config(config)
            advisory_exit_check(
                "ruff format",
                [formatter["command"], *formatter["args"], "--config", str(config), *python_files],
                drift_exit_codes=formatter["drift_exit_codes"],
            )
            run([lint_policy["command"], *lint_policy["args"], "--config", str(config), *python_files])
    if (ROOT / "frontend" / "go.mod").is_file():
        result = frontend("lint", "all")
        if result:
            return result
    print("PASS lint checks completed")
    return 0


def test_all() -> int:
    system_check()
    for service in canonical_services():
        module = ROOT / "services" / service
        if (module / "go.mod").is_file():
            ensure_developer("go")
            run(["go", "test", "./..."], cwd=module)
            run(["go", "vet", "./..."], cwd=module)
    if (ROOT / "frontend" / "go.mod").is_file():
        frontend("test", "all")
    print("PASS test checks completed")
    return 0


def changed_paths(base: str, head: str) -> list[str]:
    if head == "WORKTREE":
        tracked = git("diff", "--name-only", "--diff-filter=ACMRTUXB", base, "--").splitlines()
        untracked = git("ls-files", "--others", "--exclude-standard").splitlines()
        return sorted(set(filter(None, tracked + untracked)))
    return sorted(
        set(filter(None, git("diff", "--name-only", "--diff-filter=ACMRTUXB", base, head, "--").splitlines()))
    )


def worktree_tree_sha() -> str:
    """Hash the commit tree represented by the current worktree without mutating the real index."""
    index_path = Path(git("rev-parse", "--path-format=absolute", "--git-path", "index").strip())
    with tempfile.TemporaryDirectory(prefix="ecommerce-worktree-index-") as temp_dir:
        temporary_index = Path(temp_dir) / "index"
        env = os.environ.copy()
        env["GIT_INDEX_FILE"] = str(temporary_index)
        if index_path.is_file():
            shutil.copy2(index_path, temporary_index)
        else:
            run(["git", "read-tree", "--empty"], env=env)
        run(["git", "add", "-A", "--"], env=env)
        tree_sha = output(["git", "write-tree"], env=env).strip()
    if not re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", tree_sha):
        raise RuntimeError(f"invalid worktree tree SHA: {tree_sha!r}")
    return tree_sha


def _load_promotable_worktree_evidence(base_ref: str) -> dict | None:
    path = CONTEXT / "evidence" / "worktree.json"
    if not path.is_file():
        return None
    try:
        evidence = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    current_head = git("rev-parse", "HEAD").strip()
    base_sha = git("rev-parse", base_ref).strip()
    current_tree = worktree_tree_sha()
    if (
        not _supported_evidence_schema(evidence, 5)
        or evidence.get("evidence_kind") != "worktree"
        or evidence.get("status") != "PASS"
        or evidence.get("exact_commit_evidence") is not False
        or evidence.get("head_ref") != "WORKTREE"
        or evidence.get("head_sha") != current_head
        or evidence.get("source_head_sha") != current_head
        or evidence.get("source_tree_sha") != current_tree
        or evidence.get("base_sha") != base_sha
        or evidence.get("head_tree_sha") != current_tree
        or evidence.get("qualification_identity") != qualification_identity()
        or not _fresh_evidence(evidence)
        or evidence.get("verification", {}).get("tree_stable") is not True
        or evidence.get("changed_paths") != changed_paths(base_ref, "WORKTREE")
        or not _complete_gate_inventory(evidence, base_ref, "WORKTREE")
    ):
        return None
    return evidence


def _promote_worktree_evidence(base_ref: str, head: str, source: dict) -> Path | None:
    requested = git("rev-parse", head).strip()
    current = git("rev-parse", "HEAD").strip()
    if requested != current or git("status", "--porcelain", "--untracked-files=all").strip():
        return None
    base_sha = git("rev-parse", base_ref).strip()
    parents = git("rev-list", "--parents", "-n", "1", requested).split()
    source_head = str(source.get("source_head_sha", ""))
    source_tree = str(source.get("source_tree_sha", ""))
    commit_tree = git("rev-parse", f"{requested}^{{tree}}").strip()
    if (
        not _supported_evidence_schema(source, 5)
        or source.get("status") != "PASS"
        or source.get("exact_commit_evidence") is not False
        or source.get("base_sha") != base_sha
        or len(parents) != 2
        or parents[1] != source_head
        or commit_tree != source_tree
        or source.get("head_tree_sha") != source_tree
        or source.get("qualification_identity") != qualification_identity()
        or not _fresh_evidence(source)
        or not _complete_gate_inventory(source, base_ref, "WORKTREE")
    ):
        return None

    records: list[dict] = []
    for record in source.get("gates", []):
        promoted = copy.deepcopy(record)
        if promoted.get("status") == "PASS":
            source_duration = float(
                promoted.get("source_duration_seconds", promoted.get("duration_seconds", 0.0)) or 0.0
            )
            promoted["source_duration_seconds"] = source_duration
            promoted["duration_seconds"] = 0.0
            promoted["promoted_from_worktree"] = True
            promoted["promotion_source_tree_sha"] = source_tree
        records.append(promoted)

    payload = copy.deepcopy(source)
    payload.update(
        {
            "schema_version": 5,
            "evidence_kind": "exact_commit",
            "head_ref": requested,
            "head_sha": requested,
            "exact_commit_evidence": True,
            "head_tree_sha": commit_tree,
            "qualification_identity": qualification_identity(),
            "created_at_epoch": time.time(),
            "gates": records,
            "metrics": evidence_metrics(records),
            "verification": {
                "mode": "promoted-worktree",
                "source_head_sha": source_head,
                "source_tree_sha": source_tree,
                "commit_tree_sha": commit_tree,
            },
        }
    )
    destination = CONTEXT / "evidence" / f"{requested}.json"
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    saved = float(payload["metrics"].get("estimated_saved_seconds", 0.0) or 0.0)
    print(f"PASS | promoted worktree evidence | {requested} | tree {commit_tree} | saved~{saved:.3f}s")
    return destination


def _complete_gate_inventory(evidence: dict, base: str, head: str) -> bool:
    records = evidence.get("gates")
    if not isinstance(records, list) or any(not isinstance(row, dict) for row in records):
        return False
    global_names = {name for name, _ in _global_gate_commands(base, head)}
    component_names = set(_normalized_component_gates(affected(base, head)))
    names = [row.get("gate") for row in records]
    if any(not isinstance(name, str) for name in names):
        return False
    if len(names) != len(set(names)) or set(names) != global_names | component_names:
        return False
    for row in records:
        if row.get("status") == "PASS":
            if row.get("exit_code", 0) != 0:
                return False
        elif row.get("status") == "SKIP" and row["gate"] in component_names:
            command, _ = _component_command(row["gate"])
            if command is not None:
                return False
        else:
            return False
    return True


def _supported_evidence_schema(evidence: dict, minimum: int) -> bool:
    version = evidence.get("schema_version")
    return type(version) is int and minimum <= version <= 5


def _fresh_evidence(evidence: dict) -> bool:
    value = evidence.get("created_at_epoch")
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return False
    try:
        created = float(value)
    except (ValueError, OverflowError):
        return False
    return math.isfinite(created) and 0 <= time.time() - created <= 86400


def _qualification_toolchain() -> tuple[dict[str, list[str] | None], set[tuple[tuple[str, ...], bool]]]:
    """Conservatively bind declared gates and their transitive tool providers."""
    contract = json.loads((ROOT / "config/toolchain/capabilities.json").read_text(encoding="utf-8"))
    capabilities = {item["name"]: item for item in contract["capabilities"]}
    aliases = contract.get("command_capabilities", {})
    required = {name for names in contract["gate_requirements"].values() for name in names}
    required.update({"templ", "gofmt", "sysctl", "tofu"})
    runtime = any(
        "testcontainers" in source.read_text(encoding="utf-8")
        for source in (ROOT / "services").rglob("*_test.go")
    )
    commands: dict[str, list[str] | None] = {}
    probes: set[tuple[tuple[str, ...], bool]] = set()
    visited: set[str] = set()

    def visit(name: str) -> None:
        if name in visited:
            return
        visited.add(name)
        capability = capabilities.get(aliases.get(name, name), {})
        direct = capability.get("command")
        if direct:
            commands[direct] = capability.get("version_args", ["--version"])
        if name in required:
            commands.setdefault(name, {"gofmt": ["-h"], "tofu": ["version"]}.get(name, ["--version"]))
        probe = capability.get("probe")
        is_runtime = capability.get("requirement") == "optional-runtime"
        if probe and (runtime or not is_runtime):
            probes.add((tuple(probe), is_runtime))
            commands.setdefault(probe[0], None)
        for dependency in capability.get("requires", []):
            visit(dependency)
        if capability.get("provider"):
            visit(capability["provider"])

    for name in sorted(required):
        visit(name)
    return commands, probes


def qualification_identity() -> str:
    """Bind reusable evidence to validator/configuration and actual gate runners."""
    digest = hashlib.sha256()
    for relative in (
        "scripts/repoctl.py",
        "scripts/ci-affected.rb",
        "config/contracts/ci-evidence.yaml",
        "config/contracts/ci-topology.yaml",
        "config/toolchain/versions.env",
        "config/toolchain/capabilities.json",
    ):
        source = ROOT / relative
        digest.update(relative.encode())
        digest.update(source.read_bytes())
    controller = Path(_controller_command()[1])
    if not controller.is_absolute():
        controller = ROOT / controller
    digest.update(b"executed-controller")
    digest.update(controller.read_bytes())
    digest.update(sys.version.encode())
    interpreter = Path(sys.executable).resolve()
    digest.update(json.dumps([str(interpreter), sys.prefix, sys.base_prefix]).encode())
    with interpreter.open("rb") as handle:
        digest.update(hashlib.file_digest(handle, "sha256").digest())
    commands, probes = _qualification_toolchain()
    for command, version_args in sorted(commands.items()):
        executable = shutil.which(command)
        digest.update(command.encode())
        digest.update((executable or "missing").encode())
        if executable:
            with Path(executable).open("rb") as handle:
                digest.update(hashlib.file_digest(handle, "sha256").digest())
            if version_args is not None:
                result = run([executable, *version_args], check=False, capture=True)
                digest.update(json.dumps([result.returncode, result.stdout, result.stderr]).encode())
    for command, runtime in sorted(probes):
        executable = shutil.which(command[0])
        digest.update(json.dumps(command).encode())
        if not executable:
            digest.update(b"missing-probe")
            continue
        args = list(command)
        if command == ("docker", "info"):
            args += ["--format", "{{json .}}"]
        result = run([executable, *args[1:]], check=False, capture=True)
        value = result.stdout
        if command == ("docker", "info"):
            info = json.loads(value)
            value = json.dumps(
                {
                    key: info.get(key)
                    for key in (
                        "ID", "ServerVersion", "Driver", "DockerRootDir", "OSType",
                        "Architecture", "KernelVersion", "OperatingSystem", "CgroupDriver",
                        "CgroupVersion", "SecurityOptions", "Runtimes", "DefaultRuntime", "DriverStatus",
                    )
                },
                sort_keys=True,
            )
        digest.update(json.dumps([result.returncode, value, result.stderr]).encode())
    for name in ("GOFLAGS", "CGO_ENABLED", "ANSIBLE_CONFIG", "ANSIBLE_COLLECTIONS_PATH"):
        digest.update(name.encode())
        digest.update(os.environ.get(name, "").encode())
    return digest.hexdigest()


def _valid_exact_evidence(base_ref: str, head: str) -> Path | None:
    requested = git("rev-parse", head).strip()
    if requested != git("rev-parse", "HEAD").strip():
        return None
    if git("status", "--porcelain", "--untracked-files=all").strip():
        return None
    path = CONTEXT / "evidence" / f"{requested}.json"
    if not path.is_file():
        return None
    try:
        evidence = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    if (
        not _supported_evidence_schema(evidence, 5)
        or evidence.get("status") != "PASS"
        or evidence.get("exact_commit_evidence") is not True
        or evidence.get("head_sha") != requested
        or evidence.get("base_sha") != git("rev-parse", base_ref).strip()
        or evidence.get("head_tree_sha") != git("rev-parse", f"{requested}^{{tree}}").strip()
        or evidence.get("changed_paths") != changed_paths(base_ref, head)
        or evidence.get("qualification_identity") != qualification_identity()
        or not _fresh_evidence(evidence)
        or not _complete_gate_inventory(evidence, base_ref, head)
    ):
        return None
    return path

def affected(base: str, head: str, *, strict_unknown: bool = False) -> list[str]:
    require("ruby")
    command = ["ruby", "scripts/ci-affected.rb", "--base", base, "--head", head, "--format", "json"]
    if strict_unknown:
        command.append("--strict-unknown")
    p = run(command, capture=True)
    return json.loads(p.stdout)


def _run_gate(name: str, command: list[str], records: list[dict], env: dict[str, str] | None = None) -> bool:
    logs = CONTEXT / "logs"
    logs.mkdir(parents=True, exist_ok=True)
    log_path = logs / f"{name.replace(':', '-').replace('/', '-')}.log"
    start = time.monotonic()
    with log_path.open("w", encoding="utf-8") as log:
        p = subprocess.run(command, cwd=ROOT, env=env, text=True, stdout=log, stderr=subprocess.STDOUT)
    duration = round(time.monotonic() - start, 3)
    records.append(
        {
            "gate": name,
            "status": "PASS" if p.returncode == 0 else "FAIL",
            "exit_code": p.returncode,
            "duration_seconds": duration,
            "command": command,
            "log": str(log_path.relative_to(ROOT)),
        }
    )
    print(f"{'PASS' if p.returncode == 0 else 'FAIL'} {name} ({duration:.3f}s)")
    if p.returncode:
        print("\n".join(log_path.read_text(encoding="utf-8", errors="replace").splitlines()[-60:]), file=sys.stderr)
    return p.returncode == 0


def _incremental_parent_evidence(base: str, head: str) -> tuple[str | None, dict | None]:
    """Return direct-parent evidence only when every exactness invariant holds."""
    if head == "WORKTREE":
        return None, None
    head_sha = git("rev-parse", head).strip()
    parents = git("rev-list", "--parents", "-n", "1", head_sha).split()
    if len(parents) != 2:
        return None, None
    parent_sha = parents[1]
    evidence_path = CONTEXT / "evidence" / f"{parent_sha}.json"
    if not evidence_path.is_file() and os.environ.get("CI_EVIDENCE_REPOSITORY", "").strip():
        try:
            fetch_evidence(ROOT, CONTEXT, parent_sha)
            print(f"INFO fetched authenticated parent evidence {parent_sha[:12]}")
        except RuntimeError as exc:
            print(f"INFO remote parent evidence unavailable; full verification required: {exc}", file=sys.stderr)
    if not evidence_path.is_file():
        return None, None
    try:
        evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None, None
    base_sha = git("rev-parse", base).strip()
    if (
        not _supported_evidence_schema(evidence, 5)
        or evidence.get("status") != "PASS"
        or evidence.get("exact_commit_evidence") is not True
        or evidence.get("head_sha") != parent_sha
        or evidence.get("base_sha") != base_sha
        or evidence.get("head_tree_sha") != git("rev-parse", f"{parent_sha}^{{tree}}").strip()
        or evidence.get("qualification_identity") != qualification_identity()
        or not _fresh_evidence(evidence)
        or not _complete_gate_inventory(evidence, base, parent_sha)
    ):
        return None, None
    return parent_sha, evidence


def _reuse_gate(name: str, parent_sha: str, parent_evidence: dict, records: list[dict]) -> bool:
    source = next((gate for gate in parent_evidence.get("gates", []) if gate.get("gate") == name), None)
    if not source or source.get("status") != "PASS":
        return False
    source_duration = float(source.get("source_duration_seconds", source.get("duration_seconds", 0.0)) or 0.0)
    original_execution_sha = source.get("original_execution_sha") or source.get("reused_from_sha") or parent_sha
    records.append(
        {
            "gate": name,
            "status": "PASS",
            "exit_code": 0,
            "duration_seconds": 0.0,
            "reused_from_sha": parent_sha,
            "original_execution_sha": original_execution_sha,
            "source_duration_seconds": source_duration,
            "reuse_reason": "direct-parent exact PASS; strict delta has no affected inputs for this gate",
        }
    )
    print(f"PASS | reused {parent_sha} | {name} | saved~{source_duration:.3f}s")
    return True


def _controller_command(*args: str) -> list[str]:
    controller = os.environ.get("REPOCTL_TRUSTED_CONTROLLER", "scripts/repoctl.py").strip() or "scripts/repoctl.py"
    return [sys.executable, controller, *args]


def _require_clean_exact_checkout(command: str, head: str) -> tuple[str, str] | None:
    requested = git("rev-parse", head).strip()
    current = git("rev-parse", "HEAD").strip()
    if requested != current:
        fail(f"{command} head mismatch: requested {requested}, checked out {current}")
        return None
    if git("status", "--porcelain", "--untracked-files=all").strip():
        fail(f"{command} requires a clean exact-SHA checkout")
        return None
    return requested, current


def _normalized_component_gates(components: list[str]) -> list[str]:
    values = [component for component in components if component != "global"]
    both_frontends = "frontend:storefront" in values and "frontend:admin" in values
    if both_frontends:
        values = [component for component in values if not component.startswith("frontend:")]
        values.append("frontend:all")
    return sorted(set(values))


def _component_command(component: str) -> tuple[list[str] | None, str | None]:
    if component == "none":
        return None, "no affected component gate"
    if component.startswith("service:"):
        service = component.split(":", 1)[1]
        if not (ROOT / "services" / service / "go.mod").is_file():
            return None, "canonical service not implemented"
        return _controller_command("service", service), None
    if component.startswith("frontend:"):
        return _controller_command("frontend", "check", component.split(":", 1)[1]), None
    if component == "platform:terraform":
        return _controller_command("terraform"), None
    if component == "platform:ansible":
        return _controller_command("ansible"), None
    if component == "system":
        return _controller_command("system"), None
    raise RuntimeError(f"unsupported affected component: {component}")


def _global_gate_commands(base: str, head: str) -> list[tuple[str, list[str]]]:
    return [
        ("governance", _controller_command("governance")),
        ("runtime-efficiency", _controller_command("runtime-efficiency")),
        ("contracts", _controller_command("contracts", "--base", base, "--head", head)),
        ("automation", _controller_command("automation-policy")),
        ("security", _controller_command("security")),
    ]


def _record_delivery_wall(evidence_path: Path, evidence: dict, started: float) -> float:
    wall = round(time.monotonic() - started, 3)
    metrics = evidence.setdefault("metrics", evidence_metrics(evidence.get("gates", [])))
    metrics["deliver_wall_seconds"] = wall
    evidence_path.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(
        f"DELIVER_METRICS wall={wall:.3f}s executed={metrics.get('executed_gates', 0)} reused={metrics.get('reused_gates', 0)}"
    )
    return wall


def _record_path(record_dir: Path, label: str) -> Path:
    record_dir.mkdir(parents=True, exist_ok=True)
    safe = re.sub(r"[^A-Za-z0-9_.-]+", "-", label).strip("-") or "record"
    return record_dir / f"{safe}.json"


def _write_record(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def tekton_plan(base: str, head: str, record_dir: str, result_path: str) -> int:
    exact = _require_clean_exact_checkout("tekton-plan", head)
    if exact is None:
        return 2
    requested, current = exact
    base_sha = git("rev-parse", base).strip()
    components = affected(base, head)
    gates = _normalized_component_gates(components)
    parent_sha, parent_evidence = _incremental_parent_evidence(base, head)
    delta_components: set[str] = set()
    verification: dict = {"mode": "full"}
    reused: list[dict] = []
    execute: list[str] = []

    if parent_sha and parent_evidence:
        delta_paths = changed_paths(parent_sha, head)
        delta_components = set(affected(parent_sha, head, strict_unknown=True))
        verification = {
            "mode": "incremental",
            "parent_sha": parent_sha,
            "delta_paths": delta_paths,
            "delta_components": sorted(delta_components),
        }

    for gate in gates:
        delta_hit = gate in delta_components
        if gate == "frontend:all":
            delta_hit = bool({"frontend:storefront", "frontend:admin"} & delta_components)
        if parent_sha and parent_evidence and not delta_hit:
            if _reuse_gate(gate, parent_sha, parent_evidence, reused):
                continue
        execute.append(gate)

    directory = Path(record_dir)
    plan = {
        "schema_version": 1,
        "base_ref": base,
        "base_sha": base_sha,
        "head_ref": head,
        "head_sha": requested,
        "changed_paths": changed_paths(base, head),
        "affected_components": components,
        "component_gates": gates,
        "execute_components": execute,
        "reused_records": reused,
        "verification": verification,
    }
    _write_record(_record_path(directory, "plan"), plan)
    output_components = execute or ["none"]
    Path(result_path).write_text(json.dumps(output_components), encoding="utf-8")
    target = os.environ.get("CI_STATUS_TARGET_URL", "").strip()
    publish_remote_status(requested, "pending", "Tekton affected-only verification running", target)
    print(f"PASS tekton-plan exact {requested}: execute={len(execute)} reused={len(reused)}")
    return 0


def ci_global(base: str, head: str, record_dir: str) -> int:
    exact = _require_clean_exact_checkout("ci-global", head)
    if exact is None:
        return 2
    requested, _ = exact
    records: list[dict] = []
    env = os.environ.copy()
    env.update({"BASE": base, "HEAD": head})
    rc = 0
    for name, command in _global_gate_commands(base, head):
        if not _run_gate(name, command, records, env):
            rc = 1
            break
    _write_record(_record_path(Path(record_dir), "global"), {"head_sha": requested, "records": records})
    return rc


def ci_component(component: str, base: str, head: str, record_dir: str) -> int:
    exact = _require_clean_exact_checkout("ci-component", head)
    if exact is None:
        return 2
    requested, _ = exact
    command, reason = _component_command(component)
    records: list[dict] = []
    if command is None:
        records.append({"gate": component, "status": "SKIP", "reason": reason, "duration_seconds": 0.0})
        rc = 0
    else:
        env = os.environ.copy()
        env.update({"BASE": base, "HEAD": head})
        rc = 0 if _run_gate(component, command, records, env) else 1
    _write_record(_record_path(Path(record_dir), f"component-{component}"), {"head_sha": requested, "records": records})
    return rc


def ci_finalize(base: str, head: str, record_dir: str) -> int:
    directory = Path(record_dir)
    plan_path = _record_path(directory, "plan")
    exact = _require_clean_exact_checkout("ci-finalize", head)
    if exact is None:
        return 2
    requested, _ = exact
    base_sha = git("rev-parse", base).strip()
    target = os.environ.get("CI_STATUS_TARGET_URL", "").strip()
    if not plan_path.is_file():
        publish_remote_status(requested, "failure", "Tekton plan evidence is missing", target)
        return fail("Tekton finalizer missing plan record", 1)
    plan = json.loads(plan_path.read_text(encoding="utf-8"))
    if plan.get("head_sha") != requested or plan.get("base_sha") != base_sha:
        publish_remote_status(requested, "failure", "Tekton plan SHA/base mismatch", target)
        return fail("Tekton plan does not bind the exact head/base", 1)

    records: list[dict] = []
    global_path = _record_path(directory, "global")
    if global_path.is_file():
        records.extend(json.loads(global_path.read_text(encoding="utf-8")).get("records", []))
    records.extend(plan.get("reused_records", []))
    for path in sorted(directory.glob("component-*.json")):
        payload = json.loads(path.read_text(encoding="utf-8"))
        for record in payload.get("records", []):
            if record.get("gate") != "none":
                records.append(record)

    expected = {name for name, _ in _global_gate_commands(base, head)} | set(plan.get("component_gates", []))
    by_gate: dict[str, dict] = {}
    duplicates: set[str] = set()
    for record in records:
        gate = str(record.get("gate", ""))
        if not gate:
            continue
        if gate in by_gate:
            duplicates.add(gate)
        by_gate[gate] = record
    missing = expected - set(by_gate)
    bad = sorted(
        gate for gate, record in by_gate.items() if gate in expected and record.get("status") not in {"PASS", "SKIP"}
    )
    if missing or duplicates or bad:
        description = f"Tekton incomplete/failed: missing={len(missing)} duplicate={len(duplicates)} failed={len(bad)}"
        publish_remote_status(requested, "failure", description[:140], target)
        return fail(description, 1)

    evidence = write_evidence(
        base,
        head,
        list(plan.get("changed_paths", [])),
        list(plan.get("affected_components", [])),
        [by_gate[name] for name in sorted(expected)],
        dict(plan.get("verification", {"mode": "full"})),
    )
    if os.environ.get("CI_EVIDENCE_REPOSITORY", "").strip():
        published = publish_evidence(ROOT, evidence)
        print(f"PASS evidence published {published['digest_reference']}")
    metrics = json.loads(evidence.read_text(encoding="utf-8")).get("metrics", {})
    publish_remote_status(
        requested,
        "success",
        f"PASS: {metrics.get('executed_gates', 0)} executed, {metrics.get('reused_gates', 0)} reused",
        target,
    )
    return 0


def evidence_publish_command(path: str) -> int:
    result = publish_evidence(ROOT, Path(path))
    print(json.dumps(result, sort_keys=True))
    return 0


def evidence_fetch_command(sha: str) -> int:
    path = fetch_evidence(ROOT, CONTEXT, sha)
    print(path.relative_to(ROOT))
    return 0


def evidence_compare_command(full_path: str, incremental_path: str) -> int:
    result = compare_evidence(Path(full_path), Path(incremental_path))
    destination = (
        CONTEXT
        / f"evidence-comparison-{str(result.get('full_head_sha'))[:12]}-{str(result.get('incremental_head_sha'))[:12]}.json"
    )
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2, sort_keys=True))
    print(f"EVIDENCE_COMPARISON {destination.relative_to(ROOT)}")
    return 0


def github_exact_ci_status(gh: str, head_sha: str) -> str:
    response = run(
        [gh, "api", f"repos/{{owner}}/{{repo}}/commits/{head_sha}/status"],
        check=False,
        capture=True,
    )
    if response.returncode:
        return "no remote CI status present"
    try:
        payload = json.loads(response.stdout or "{}")
    except json.JSONDecodeError:
        return "no remote CI status present"
    statuses = [status for status in payload.get("statuses", []) if status.get("context") == REMOTE_STATUS_CONTEXT]
    if not statuses:
        return "no remote CI status present"
    latest = statuses[0]
    return f"{latest.get('state', 'unknown')} | {REMOTE_STATUS_CONTEXT} | {head_sha}"


def write_evidence(
    base: str, head: str, paths: list[str], components: list[str], records: list[dict], verification: dict | None = None
) -> Path:
    base_sha = git("rev-parse", base).strip()
    current_head_sha = git("rev-parse", "HEAD").strip()
    head_sha = current_head_sha if head == "WORKTREE" else git("rev-parse", head).strip()
    clean = not git("status", "--porcelain", "--untracked-files=all").strip()
    exact = head != "WORKTREE" and clean and current_head_sha == head_sha
    verification_data = verification or {"mode": "full"}
    payload = {
        "schema_version": 5,
        "evidence_kind": "worktree" if head == "WORKTREE" else "exact_commit",
        "base_ref": base,
        "base_sha": base_sha,
        "head_ref": head,
        "head_sha": head_sha,
        "exact_commit_evidence": exact,
        "head_tree_sha": worktree_tree_sha() if head == "WORKTREE" else git("rev-parse", f"{head_sha}^{{tree}}").strip(),
        "qualification_identity": qualification_identity(),
        "created_at_epoch": time.time(),
        "status": "FAIL" if any(r["status"] == "FAIL" for r in records) else "PASS",
        "changed_paths": paths,
        "affected_components": components,
        "gates": records,
        "metrics": evidence_metrics(records),
        "verification": verification_data,
    }
    if head == "WORKTREE":
        payload["source_head_sha"] = verification_data.get("source_head_sha", current_head_sha)
        payload["source_tree_sha"] = verification_data.get("source_tree_sha")
    identity = head_sha if head != "WORKTREE" else "worktree"
    destination = CONTEXT / "evidence" / f"{identity}.json"
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"EVIDENCE {destination.relative_to(ROOT)}")
    return destination


def verify_change(base: str, head: str) -> int:
    source_head_sha: str | None = None
    source_tree_sha: str | None = None
    if head != "WORKTREE":
        requested_head_sha = git("rev-parse", head).strip()
        current_head_sha = git("rev-parse", "HEAD").strip()
        if requested_head_sha != current_head_sha:
            return fail(f"verify-change head mismatch: requested {requested_head_sha}, checked out {current_head_sha}")
        if git("status", "--porcelain", "--untracked-files=all").strip():
            return fail("verify-change exact head requires a clean worktree")
    else:
        source_head_sha = git("rev-parse", "HEAD").strip()
        source_tree_sha = worktree_tree_sha()

    paths = changed_paths(base, head)
    components = affected(base, head)
    records: list[dict] = []
    env = os.environ.copy()
    env.update({"BASE": base, "HEAD": head})

    def run_stable_gate(name: str, command: list[str]) -> bool:
        before_tree = worktree_tree_sha() if head == "WORKTREE" else ""
        ok = _run_gate(name, command, records, env)
        if head != "WORKTREE":
            return ok
        after_tree = worktree_tree_sha()
        if after_tree == before_tree:
            return ok
        mutated_paths = git("diff", "--name-only", before_tree, after_tree).splitlines()
        if records and records[-1].get("gate") == name:
            records[-1]["status"] = "FAIL"
            records[-1]["exit_code"] = 1
            records[-1]["reason"] = "gate mutated worktree"
            records[-1]["mutated_paths"] = mutated_paths
        print(f"FAIL {name} mutated worktree: {mutated_paths}", file=sys.stderr)
        return False

    parent_sha, parent_evidence = _incremental_parent_evidence(base, head)
    delta_components: set[str] = set()
    verification: dict = {"mode": "full"}
    if head == "WORKTREE":
        verification = {
            "mode": "worktree",
            "source_head_sha": source_head_sha,
            "source_tree_sha": source_tree_sha,
        }
    elif parent_sha and parent_evidence:
        delta_paths = changed_paths(parent_sha, head)
        delta_components = set(affected(parent_sha, head, strict_unknown=True))
        verification = {
            "mode": "incremental",
            "parent_sha": parent_sha,
            "delta_paths": delta_paths,
            "delta_components": sorted(delta_components),
        }
        print(f"INFO incremental verification from exact parent {parent_sha[:12]}")

    global_commands = _global_gate_commands(base, head)
    for name, command in global_commands:
        if not run_stable_gate(name, command):
            write_evidence(base, head, paths, components, records, verification)
            return 1

    combined = "frontend:storefront" in components and "frontend:admin" in components
    if combined:
        frontend_delta = bool({"frontend:storefront", "frontend:admin"} & delta_components)
        reused = bool(
            parent_evidence
            and parent_sha
            and not frontend_delta
            and _reuse_gate("frontend:all", parent_sha, parent_evidence, records)
        )
        if not reused and not _run_gate("frontend:all", _controller_command("frontend", "check", "all"), records, env):
            write_evidence(base, head, paths, components, records, verification)
            return 1

    for component in components:
        if component == "global" or (combined and component.startswith("frontend:")):
            continue
        command, skip_reason = _component_command(component)
        if command is None:
            records.append({"gate": component, "status": "SKIP", "reason": skip_reason, "duration_seconds": 0.0})
            continue
        if parent_evidence and parent_sha and component not in delta_components:
            if _reuse_gate(component, parent_sha, parent_evidence, records):
                continue
        if not run_stable_gate(component, command):
            write_evidence(base, head, paths, components, records, verification)
            return 1

    if head == "WORKTREE":
        final_tree_sha = worktree_tree_sha()
        verification["final_tree_sha"] = final_tree_sha
        verification["tree_stable"] = final_tree_sha == source_tree_sha
        if final_tree_sha != source_tree_sha:
            records.append(
                {
                    "gate": "worktree-stability",
                    "status": "FAIL",
                    "exit_code": 1,
                    "duration_seconds": 0.0,
                    "reason": "tracked/untracked commit tree changed during verification",
                }
            )
            write_evidence(base, head, paths, components, records, verification)
            return fail("worktree changed during verification; evidence is not promotable", 1)

    ev = write_evidence(base, head, paths, components, records, verification)
    if head != "WORKTREE" and git("status", "--porcelain", "--untracked-files=all").strip():
        return fail(f"exact evidence requires a clean tree: {ev.relative_to(ROOT)}", 2)
    return 0


def diff_context(base: str) -> int:
    CONTEXT.mkdir(exist_ok=True)
    paths = changed_paths(base, "WORKTREE")
    stat = git("diff", "--stat", base)
    diff = git("diff", "--unified=2", base, "--")
    out = CONTEXT / "diff.md"
    out.write_text(
        "# Diff context\n\n## Files\n"
        + "\n".join(f"- `{p}`" for p in paths)
        + "\n\n## Stat\n```text\n"
        + stat[:12000]
        + "\n```\n\n## Diff\n```diff\n"
        + diff[:28000]
        + "\n```\n",
        encoding="utf-8",
    )
    print(out.relative_to(ROOT))
    return 0


def failure_context(gate: str, component: str) -> int:
    if component:
        if component.startswith("service:"):
            cmd = [sys.executable, "scripts/repoctl.py", "service", component.split(":", 1)[1]]
        elif component.startswith("frontend:"):
            cmd = [sys.executable, "scripts/repoctl.py", "frontend", "check", component.split(":", 1)[1]]
        elif component == "platform:terraform":
            cmd = [sys.executable, "scripts/repoctl.py", "terraform"]
        elif component == "platform:ansible":
            cmd = [sys.executable, "scripts/repoctl.py", "ansible"]
        else:
            return fail(f"unsupported COMPONENT: {component}")
        name = component.replace(":", "-")
    else:
        allowed = {
            "governance",
            "runtime-efficiency",
            "contracts",
            "lint",
            "test",
            "security",
            "terraform",
            "ansible",
            "system",
            "automation-policy",
        }
        if gate not in allowed:
            return fail(f"unsupported GATE: {gate}")
        cmd = [sys.executable, "scripts/repoctl.py", gate]
        name = gate
    p = run(cmd, check=False, capture=True)
    text = (p.stdout or "") + (p.stderr or "")
    lines = text.splitlines()
    keywords = re.compile(r"FAIL|FAILED|ERROR|error:|fatal:|panic:|cannot use|undefined|make: \*\*\*", re.I)
    hits = [i for i, line in enumerate(lines) if keywords.search(line)]
    chosen: set[int] = set()
    for i in hits:
        chosen.update(range(max(0, i - 3), min(len(lines), i + 4)))
    relevant = [lines[i] for i in sorted(chosen)] if chosen else lines[-120:]
    CONTEXT.mkdir(exist_ok=True)
    path = CONTEXT / f"failure-{name}.md"
    path.write_text(
        f"# Failure context\nGATE: {name}\nSTATUS: {'PASS' if p.returncode == 0 else 'FAIL'}\nEXIT_CODE: {p.returncode}\n\n## Relevant output\n```text\n"
        + "\n".join(relevant[:220])
        + "\n```\n",
        encoding="utf-8",
    )
    print(path.relative_to(ROOT))
    return p.returncode


def doctor() -> int:
    expected = [
        "git",
        "make",
        "go",
        "gofmt",
        "python3",
        "pipx",
        "pre-commit",
        "ansible",
        "ansible-lint",
        "molecule",
        "terraform",
        "tflint",
        "trivy",
        "checkov",
        "gitleaks",
        "ggshield",
        "semgrep",
        "syft",
        "cosign",
        "oras",
        "rg",
        "fd",
        "yq",
        "ast-grep",
        "kubeconform",
        "conftest",
        "opa",
        "kubectl",
        "helm",
        "kustomize",
        "docker",
        "bazel",
        "bazelisk",
        "nx",
        "oasdiff",
        "oapi-codegen",
        "oxlint",
        "oxfmt",
        "ruff",
    ]
    rc = 0
    for cmd in expected:
        path = shutil.which(cmd)
        print(f"{'PASS' if path else 'FAIL'} {cmd:24} {path or 'missing'}")
        rc |= 0 if path else 1
    if shutil.which("docker") and run(["docker", "info"], check=False, capture=True).returncode == 0:
        print("PASS docker-daemon reachable")
    else:
        print("FAIL docker-daemon unreachable")
        rc = 1
    rc |= ansible_collections_check()
    return rc


def git_sync() -> int:
    branch = git("branch", "--show-current").strip()
    if not branch:
        return fail("git-sync detached HEAD")
    if git("status", "--porcelain", "--untracked-files=all").strip():
        return fail("git-sync requires clean tree")
    run(["git", "fetch", "origin", "--prune"])
    run(["git", "merge", "--ff-only", f"origin/{branch}"])
    print(f"PASS git-sync {branch}")
    return 0


def _validate_repository_delivery_policy(policy: dict) -> dict:
    if not isinstance(policy, dict):
        raise RuntimeError("review-policy repository_delivery must be a mapping")
    required_sections = {"publish", "pull_request", "merge", "cleanup"}
    missing = sorted(required_sections - set(policy))
    if missing:
        raise RuntimeError(f"review-policy repository_delivery missing sections: {missing}")
    if policy.get("forge") != "github":
        raise RuntimeError("repository_delivery forge must be github")
    if not str(policy.get("default_branch", "")).strip():
        raise RuntimeError("repository_delivery default_branch is required")

    publish_policy = policy["publish"]
    pull_request_policy = policy["pull_request"]
    merge_policy = policy["merge"]
    cleanup_policy = policy["cleanup"]
    for section_name, section in (
        ("publish", publish_policy),
        ("pull_request", pull_request_policy),
        ("merge", merge_policy),
        ("cleanup", cleanup_policy),
    ):
        if not isinstance(section, dict):
            raise RuntimeError(f"review-policy repository_delivery.{section_name} must be a mapping")
    required_invariants = (
        (publish_policy.get("qualification") == "exact-sha", "publish qualification must be exact-sha"),
        (publish_policy.get("exact_evidence_required") is True, "publish exact evidence must be required"),
        (publish_policy.get("force_push") == "forbidden", "force-push must be forbidden"),
        (
            publish_policy.get("push_target") == "current-feature-branch",
            "publish target must be the current feature branch",
        ),
        (
            publish_policy.get("direct_default_branch_write") == "forbidden",
            "direct default-branch writes must be forbidden",
        ),
        (pull_request_policy.get("required") is True, "pull request must be required"),
        (pull_request_policy.get("head_sha_binding") == "exact", "pull request head binding must be exact"),
        (pull_request_policy.get("draft_merge") == "forbidden", "draft PR merge must be forbidden"),
        (
            pull_request_policy.get("record_after_merge") == "retained-by-forge",
            "merged PR record must be retained by the forge",
        ),
        (merge_policy.get("method") == "merge", "merge method must be merge"),
        (merge_policy.get("match_head_commit") == "required", "merge must match the exact head commit"),
        (merge_policy.get("branch_protection") == "required", "branch protection must be required"),
        (merge_policy.get("required_checks") == "when-configured", "required checks must be enforced when configured"),
        (
            merge_policy.get("bypass_branch_protection") == "forbidden",
            "branch-protection bypass must be forbidden",
        ),
        (cleanup_policy.get("merged_pr_state") == "merged-closed", "merged PR state must be merged-closed"),
        (cleanup_policy.get("remote_branch") == "delete", "remote feature branch cleanup must be delete"),
        (cleanup_policy.get("local_branch") == "delete", "local feature branch cleanup must be delete"),
    )
    for valid, message in required_invariants:
        if not valid:
            raise RuntimeError(f"invalid repository_delivery contract: {message}")
    return policy


def repository_delivery_policy() -> dict:
    review_policy = ruby_yaml("config/contracts/review-policy.yaml")
    return _validate_repository_delivery_policy(review_policy.get("repository_delivery") or {})


def _remote_ref_sha(ref: str) -> str:
    result = run(["git", "rev-parse", "--verify", ref], check=False, capture=True)
    return result.stdout.strip() if result.returncode == 0 else ""


def publish(base: str, message: str) -> int:
    policy = repository_delivery_policy()
    default_branch = str(policy["default_branch"])
    base_name = base.removeprefix("origin/")
    if base_name != default_branch:
        return fail(f"publish base must match contract default branch {default_branch!r}")
    branch = git("branch", "--show-current").strip()
    if not branch or branch in {default_branch, "master"}:
        return fail("publish refuses detached/default branch")
    run(["git", "fetch", "origin", "--prune"])
    base_ref = f"origin/{base_name}"
    if run(["git", "merge-base", "--is-ancestor", base_ref, "HEAD"], check=False).returncode:
        return fail(f"branch is not based on current {base_ref}")

    dirty = bool(git("status", "--porcelain", "--untracked-files=all").strip())
    promotable = _load_promotable_worktree_evidence(base_ref) if dirty else None
    if dirty:
        if not message:
            return fail("dirty tree requires MSG/TITLE")
        if promotable:
            print("INFO exact worktree PASS matches current parent/base/tree; commit will attempt evidence promotion")
        else:
            print("INFO no promotable worktree evidence; exact-SHA verification will run after commit")
        run(["git", "add", "-A"])
        commit_env = os.environ.copy()
        commit_env["SKIP"] = ",".join(filter(None, [commit_env.get("SKIP", ""), "affected-precommit"]))
        run(["git", "commit", "-m", message], env=commit_env)

    head = git("rev-parse", "HEAD").strip()
    exact_evidence: Path | None = None
    if promotable is not None:
        exact_evidence = _promote_worktree_evidence(base_ref, head, promotable)
        if exact_evidence is None:
            print("INFO worktree evidence promotion invariants changed; falling back to exact-SHA verification")
    if exact_evidence is None:
        exact_evidence = _valid_exact_evidence(base_ref, head)
        if exact_evidence is not None:
            print(f"PASS publish: reusing existing exact evidence {exact_evidence.relative_to(ROOT)}")
    if exact_evidence is None and verify_change(base_ref, head):
        return 1

    run(["git", "push", "-u", "origin", "HEAD"])
    print(f"PASS publish: pushed {branch} at {head} without force")
    return 0


def deliver(base: str, title: str, message: str) -> int:
    deliver_started = time.monotonic()
    policy = repository_delivery_policy()
    review_forge = policy.get("forge")
    if review_forge != "github":
        return fail(f"repository_delivery forge must be github; got {review_forge!r}")
    base_name = base.removeprefix("origin/")
    if base_name != policy["default_branch"]:
        return fail(f"deliver base must match contract default branch {policy['default_branch']!r}")
    if publish(base_name, message or title):
        return 1
    gh = shutil.which("gh") or shutil.which("gh.exe")
    if not gh:
        return fail("GitHub CLI missing")
    branch = git("branch", "--show-current").strip()
    head = git("rev-parse", "HEAD").strip()
    evidence = CONTEXT / "evidence" / f"{head}.json"
    if not evidence.is_file():
        return fail(f"exact evidence missing for {head}")
    if not title:
        title = git("log", "-1", "--pretty=%s").strip()
    changed = (
        git("diff", "--name-only", f"origin/{base_name}...HEAD")
    )
    stat = (
        git("diff", "--stat", f"origin/{base_name}...HEAD")
    )
    ev = json.loads(evidence.read_text(encoding="utf-8"))
    metrics = ev.get("metrics") or evidence_metrics(ev.get("gates", []))
    remote_ci = github_exact_ci_status(gh, head)
    body = CONTEXT / "pr-body.md"
    body.parent.mkdir(exist_ok=True)

    def gate_source(gate: dict) -> str:
        if gate.get("promoted_from_worktree"):
            return "promoted from validated worktree tree"
        if gate.get("reused_from_sha"):
            return f"reused `{gate['reused_from_sha'][:12]}`"
        if gate.get("status") == "SKIP":
            return gate.get("reason", "not applicable")
        return "executed"

    rows = "\n".join(
        f"| `{g['gate']}` | {g['status']} | {g.get('duration_seconds', 0)} | {gate_source(g)} |" for g in ev["gates"]
    )
    body.write_text(
        f"## Summary\n\n{title}\n\n## Scope\n\n```text\n{changed}```\n\n## Diff stat\n\n```text\n{stat}```\n\n## Deterministic validation\n\n| Gate | Status | Duration (s) | Source |\n| --- | --- | ---: | --- |\n{rows}\n\n## Review evidence\n\n- Base: `{base_name}` / `{ev['base_sha']}`\n- Head branch: `{branch}`\n- Head SHA: `{head}`\n- Verification mode: `{ev.get('verification', {}).get('mode', 'full')}`\n- Exact commit evidence cache: `.context/evidence/{head}.json` (not committed)\n- Executed gates: {metrics.get('executed_gates', 0)}\n- Reused gates: {metrics.get('reused_gates', 0)}\n- Gate execution time: {metrics.get('executed_seconds', 0)} s\n- Estimated reused time: {metrics.get('estimated_saved_seconds', 0)} s\n- Remote CI exact SHA: {remote_ci}\n\n## Safety\n\nThis automation creates or refreshes the pull request only. It does not approve, merge, force-push, bypass branch protection, or mutate infrastructure.\n",
        encoding="utf-8",
    )
    existing = output(
        [
            gh,
            "pr",
            "list",
            "--head",
            branch,
            "--base",
            base_name,
            "--state",
            "open",
            "--json",
            "number,url",
            "--jq",
            '.[0] | select(.) | "\\(.number) \\(.url)"',
        ]
    ).strip()
    if existing:
        num, url = existing.split(" ", 1)
        run(
            [
                gh,
                "api",
                "--method",
                "PATCH",
                f"repos/{{owner}}/{{repo}}/pulls/{num}",
                "--raw-field",
                f"title={title}",
                "--raw-field",
                f"body={body.read_text(encoding='utf-8')}",
            ]
        )
        actual = output([gh, "api", f"repos/{{owner}}/{{repo}}/pulls/{num}", "--jq", ".head.sha"]).strip()
        if actual != head:
            return fail(f"PR head mismatch: expected {head}, got {actual}")
        _record_delivery_wall(evidence, ev, deliver_started)
        print(f"PASS deliver: refreshed PR {url} at {head}")
        return 0
    p = run(
        [
            gh,
            "pr",
            "create",
            "--base",
            base_name,
            "--head",
            branch,
            "--title",
            title,
            "--body-file",
            str(body),
        ],
        capture=True,
    )
    _record_delivery_wall(evidence, ev, deliver_started)
    print(f"PASS deliver: created PR {p.stdout.strip()} at {head}")
    return 0


def finish_pr(base: str) -> int:
    policy = repository_delivery_policy()
    base_name = base.removeprefix("origin/")
    default_branch = str(policy["default_branch"])
    if base_name != default_branch:
        return fail(f"finish-pr base must match contract default branch {default_branch!r}")

    branch = git("branch", "--show-current").strip()
    if not branch or branch in {default_branch, "master"}:
        return fail("finish-pr requires a checked-out feature branch")
    if git("status", "--porcelain", "--untracked-files=all").strip():
        return fail("finish-pr requires a clean worktree")

    gh = shutil.which("gh") or shutil.which("gh.exe")
    if not gh:
        return fail("GitHub CLI missing")

    run(["git", "fetch", "origin", "--prune"])
    base_ref = f"origin/{base_name}"
    if run(["git", "merge-base", "--is-ancestor", base_ref, "HEAD"], check=False).returncode:
        return fail(f"finish-pr branch is not based on current {base_ref}")

    head = git("rev-parse", "HEAD").strip()
    remote_head = _remote_ref_sha(f"origin/{branch}")
    if remote_head != head:
        return fail(f"finish-pr remote head mismatch: local {head}, origin/{branch} {remote_head or 'missing'}")

    evidence = _valid_exact_evidence(base_ref, head)
    if evidence is None:
        if verify_change(base_ref, head):
            return 1
        evidence = _valid_exact_evidence(base_ref, head)
    if evidence is None:
        return fail(f"finish-pr exact PASS evidence missing for {head}")

    raw_prs = output(
        [
            gh,
            "pr",
            "list",
            "--head",
            branch,
            "--base",
            base_name,
            "--state",
            "open",
            "--limit",
            "2",
            "--json",
            "number,url,headRefOid,baseRefName,isDraft",
        ]
    )
    prs = json.loads(raw_prs or "[]")
    if len(prs) != 1:
        return fail(f"finish-pr requires exactly one open PR for {branch} -> {base_name}; found {len(prs)}")
    pr = prs[0]
    number = int(pr["number"])
    if pr.get("isDraft"):
        return fail(f"finish-pr refuses draft PR #{number}")
    if pr.get("baseRefName") != base_name:
        return fail(f"finish-pr PR #{number} base mismatch: {pr.get('baseRefName')!r}")
    if pr.get("headRefOid") != head:
        return fail(f"finish-pr PR #{number} head mismatch: expected {head}, got {pr.get('headRefOid')!r}")

    protection = run(
        [gh, "api", f"repos/{{owner}}/{{repo}}/branches/{base_name}/protection"],
        check=False,
        capture=True,
    )
    if protection.returncode:
        active_rules = run(
            [gh, "api", f"repos/{{owner}}/{{repo}}/rules/branches/{base_name}"],
            check=False,
            capture=True,
        )
        if active_rules.returncode or not (active_rules.stdout or "").strip():
            detail = (
                active_rules.stderr
                or active_rules.stdout
                or protection.stderr
                or protection.stdout
                or ""
            ).strip()
            return fail(
                f"finish-pr cannot prove branch protection/ruleset for {base_name}: "
                f"{detail or 'GitHub API rejected protection queries'}"
            )

    checks = run([gh, "pr", "checks", str(number), "--required"], check=False, capture=True)
    if checks.returncode:
        detail = "\n".join(filter(None, [(checks.stdout or "").strip(), (checks.stderr or "").strip()]))
        if "no checks reported" not in detail.lower():
            if detail:
                print(detail, file=sys.stderr)
            return fail(f"finish-pr required checks are not PASS for PR #{number}")
        print(
            f"INFO finish-pr: no required GitHub checks configured for PR #{number}; "
            "exact PASS evidence and branch protection remain mandatory"
        )

    merge_method = str(policy["merge"]["method"])
    merge_flag = {"merge": "--merge", "squash": "--squash", "rebase": "--rebase"}[merge_method]
    merged = run(
        [
            gh,
            "pr",
            "merge",
            str(number),
            merge_flag,
            "--delete-branch",
            "--match-head-commit",
            head,
        ],
        check=False,
        capture=True,
    )
    if merged.returncode:
        detail = "\n".join(filter(None, [(merged.stdout or "").strip(), (merged.stderr or "").strip()]))
        if detail:
            print(detail, file=sys.stderr)
        return fail(f"finish-pr merge refused for PR #{number}")

    merged_state = json.loads(
        output([gh, "pr", "view", str(number), "--json", "state,mergedAt,headRefOid,baseRefName"])
    )
    if merged_state.get("state") != "MERGED" or not merged_state.get("mergedAt"):
        return fail(f"finish-pr PR #{number} did not reach MERGED state")
    if merged_state.get("headRefOid") != head:
        return fail(f"finish-pr merged PR #{number} no longer binds expected head {head}")

    run(["git", "fetch", "origin", "--prune"])
    remote_branch = run(
        ["git", "ls-remote", "--exit-code", "--heads", "origin", f"refs/heads/{branch}"],
        check=False,
        capture=True,
    )
    if remote_branch.returncode == 0:
        deletion = run(["git", "push", "origin", "--delete", branch], check=False, capture=True)
        if deletion.returncode:
            detail = (deletion.stderr or deletion.stdout or "").strip()
            return fail(f"finish-pr could not delete remote branch {branch}: {detail}")

    switch = run(["git", "switch", base_name], check=False, capture=True)
    if switch.returncode:
        run(["git", "switch", "-c", base_name, "--track", f"origin/{base_name}"])
    run(["git", "merge", "--ff-only", f"origin/{base_name}"])

    local_branch = run(["git", "show-ref", "--verify", "--quiet", f"refs/heads/{branch}"], check=False)
    if local_branch.returncode == 0:
        run(["git", "branch", "-d", branch])

    print(
        f"PASS finish-pr: PR #{number} merged at exact head {head}; "
        f"PR record retained by GitHub; remote/local branch {branch} removed"
    )
    return 0


def precommit() -> int:
    return verify_change("HEAD", "WORKTREE")


def prepush() -> int:
    head = git("rev-parse", "HEAD").strip()
    evidence = _valid_exact_evidence("origin/main", head)
    if evidence is not None:
        print(f"PASS prepush: reusing validated exact evidence {evidence.relative_to(ROOT)}")
        return 0
    return verify_change("origin/main", head)


def tekton_trigger_readiness_command(runtime_config: str, evidence: str) -> int:
    """Run live trigger prerequisite checks without mutating Kubernetes state."""
    if not runtime_config.strip():
        return fail("tekton-trigger-readiness requires RUNTIME_CONFIG/--runtime-config")
    from tekton_trigger_readiness import run_readiness

    return run_readiness(ROOT, ruby_yaml(runtime_config), Path(evidence))


def main() -> int:
    p = argparse.ArgumentParser()
    sub = p.add_subparsers(dest="cmd", required=True)
    for name in [
        "governance",
        "runtime-efficiency",
        "automation-policy",
        "format-check",
        "lint",
        "test",
        "security",
        "terraform",
        "ansible",
        "system",
        "doctor",
        "git-sync",
        "precommit",
        "prepush",
        "site",
        "product-run",
        "product-benchmark",
    ]:
        sub.add_parser(name)
    c = sub.add_parser("contracts")
    c.add_argument("--base", default=os.environ.get("BASE", ""))
    c.add_argument("--head", default=os.environ.get("HEAD", "WORKTREE"))
    c.add_argument("--generate", action="store_true")
    f = sub.add_parser("frontend")
    f.add_argument("action")
    f.add_argument("scope", nargs="?", default="")
    s = sub.add_parser("service")
    s.add_argument("service")
    a = sub.add_parser("affected")
    a.add_argument("--base", default=os.environ.get("BASE", "origin/main"))
    a.add_argument("--head", default=os.environ.get("HEAD", "WORKTREE"))
    a.add_argument("--json", action="store_true")
    v = sub.add_parser("verify-change")
    v.add_argument("--base", default=os.environ.get("BASE", "origin/main"))
    v.add_argument("--head", default=os.environ.get("HEAD", "WORKTREE"))
    d = sub.add_parser("diff-context")
    d.add_argument("--base", default=os.environ.get("BASE", "origin/main"))
    fc = sub.add_parser("failure-context")
    fc.add_argument("--gate", default=os.environ.get("GATE", ""))
    fc.add_argument("--component", default=os.environ.get("COMPONENT", ""))
    ctx = sub.add_parser("context")
    ctx.add_argument("task", nargs="?", default="")
    gen = sub.add_parser("api-generate")
    gen.add_argument("--target", default="go")
    gen.add_argument("--service", default="")
    gen.add_argument("--check", action="store_true")
    nx = sub.add_parser("nx-graph")
    sg = sub.add_parser("service-new")
    sg.add_argument("--service", required=True)
    sg.add_argument("--dry-run", action="store_true")
    rec = sub.add_parser("reconcile")
    rec.add_argument("--tags", required=True)
    rec.add_argument("--target-repo-root", default="")
    bz = sub.add_parser("bazel-verify")
    bz.add_argument("--base", default=os.environ.get("BASE", "origin/main"))
    bz.add_argument("--head", default=os.environ.get("HEAD", "WORKTREE"))
    rc = sub.add_parser("resource-candidate")
    rc.add_argument("--evidence", default=os.environ.get("EVIDENCE", ""))
    tkp = sub.add_parser("tekton-proof")
    tkp.add_argument("--runtime-config", default=os.environ.get("RUNTIME_CONFIG", ""))
    tkp.add_argument("--base-sha", default=os.environ.get("BASE_SHA", ""))
    tkp.add_argument("--parent-sha", default=os.environ.get("PARENT_SHA", ""))
    tkp.add_argument("--head-sha", default=os.environ.get("HEAD_SHA", ""))
    pub = sub.add_parser("publish")
    pub.add_argument("--base", default=os.environ.get("BASE", "origin/main"))
    pub.add_argument("--message", default=os.environ.get("MSG", ""))
    pubc = sub.add_parser("publish-change")
    pubc.add_argument("--base", default=os.environ.get("BASE", "origin/main"))
    pubc.add_argument("--message", default=os.environ.get("MSG", ""))
    dlv = sub.add_parser("deliver")
    dlv.add_argument("--base", default=os.environ.get("BASE", "main"))
    dlv.add_argument("--title", default=os.environ.get("TITLE", ""))
    dlv.add_argument("--message", default=os.environ.get("MSG", ""))
    fin = sub.add_parser("finish-pr")
    fin.add_argument("--base", default=os.environ.get("BASE", "main"))
    bdlv = sub.add_parser("bundle-deliver")
    bdlv.add_argument("--bundle", required=True)
    bdlv.add_argument("--expected-head", required=True)
    bdlv.add_argument("--title", required=True)
    bdlv.add_argument("--base", default=os.environ.get("BASE", "main"))
    trr = sub.add_parser("tekton-trigger-readiness")
    trr.add_argument("--runtime-config", required=True)
    trr.add_argument(
        "--evidence",
        default=os.environ.get("TEKTON_TRIGGER_READINESS_EVIDENCE", ".context/runtime/tekton-trigger-readiness.json"),
    )
    tp = sub.add_parser("tekton-plan")
    tp.add_argument("--base", required=True)
    tp.add_argument("--head", required=True)
    tp.add_argument("--record-dir", required=True)
    tp.add_argument("--result-path", required=True)
    cg = sub.add_parser("ci-global")
    cg.add_argument("--base", required=True)
    cg.add_argument("--head", required=True)
    cg.add_argument("--record-dir", required=True)
    cc = sub.add_parser("ci-component")
    cc.add_argument("--component", required=True)
    cc.add_argument("--base", required=True)
    cc.add_argument("--head", required=True)
    cc.add_argument("--record-dir", required=True)
    cf = sub.add_parser("ci-finalize")
    cf.add_argument("--base", required=True)
    cf.add_argument("--head", required=True)
    cf.add_argument("--record-dir", required=True)
    ep = sub.add_parser("evidence-publish")
    ep.add_argument("--path", required=True)
    ef = sub.add_parser("evidence-fetch")
    ef.add_argument("--sha", required=True)
    ec = sub.add_parser("evidence-compare")
    ec.add_argument("--full", required=True)
    ec.add_argument("--incremental", required=True)
    args = p.parse_args()
    try:
        if args.cmd == "governance":
            return governance()
        if args.cmd == "runtime-efficiency":
            return runtime_efficiency_check()
        if args.cmd == "contracts":
            return contracts(args.base, args.head, args.generate)
        if args.cmd == "automation-policy":
            return automation_policy()
        if args.cmd == "format-check":
            return format_check()
        if args.cmd == "lint":
            return lint_all()
        if args.cmd == "test":
            return test_all()
        if args.cmd == "security":
            return security()
        if args.cmd == "terraform":
            return terraform_check()
        if args.cmd == "ansible":
            return ansible_check()
        if args.cmd == "system":
            return system_check()
        if args.cmd == "frontend":
            return frontend(args.action, args.scope)
        if args.cmd == "site":
            return site()
        if args.cmd == "product-run":
            return product_run()
        if args.cmd == "product-benchmark":
            return product_benchmark()
        if args.cmd == "service":
            return service_check(args.service)
        if args.cmd == "affected":
            comps = affected(args.base, args.head)
            print(json.dumps(comps) if args.json else "\n".join(comps))
            return 0
        if args.cmd == "verify-change":
            return verify_change(args.base, args.head)
        if args.cmd == "diff-context":
            return diff_context(args.base)
        if args.cmd == "failure-context":
            return failure_context(args.gate, args.component)
        if args.cmd == "context":
            return run([sys.executable, "scripts/context-pack.py", "--task", args.task], check=False).returncode
        if args.cmd == "api-generate":
            return api_generate(args.target, args.service, args.check)
        if args.cmd == "nx-graph":
            materialize = run([sys.executable, "scripts/nx-graph.py"], check=False)
            if materialize.returncode:
                return materialize.returncode
            out = ROOT / ".context/nx-workspace"
            return run(
                ["nx", "graph", "--file", str(ROOT / ".context/nx-graph.html"), "--focus", "frontend-admin"], cwd=out
            ).returncode
        if args.cmd == "service-new":
            cmd = [sys.executable, "scripts/servicegen.py", "--service", args.service] + (
                ["--dry-run"] if args.dry_run else []
            )
            return run(cmd, check=False).returncode
        if args.cmd == "reconcile":
            return reconcile(args.tags, args.target_repo_root)
        if args.cmd == "bazel-verify":
            return bazel_verify(args.base, args.head)
        if args.cmd == "resource-candidate":
            return resource_candidate(args.evidence)
        if args.cmd == "tekton-proof":
            return tekton_proof(args.runtime_config, args.base_sha, args.parent_sha, args.head_sha)
        if args.cmd == "doctor":
            return doctor()
        if args.cmd == "git-sync":
            return git_sync()
        if args.cmd == "publish":
            return publish(args.base, args.message)
        if args.cmd == "publish-change":
            return publish(args.base, args.message)
        if args.cmd == "deliver":
            return deliver(args.base, args.title, args.message)
        if args.cmd == "finish-pr":
            return finish_pr(args.base)
        if args.cmd == "bundle-deliver":
            return isolated_bundle_deliver(
                ROOT, Path(__file__).resolve(), args.bundle, args.expected_head, args.title, args.base, sys.executable
            )
        if args.cmd == "tekton-trigger-readiness":
            return tekton_trigger_readiness_command(args.runtime_config, args.evidence)
        if args.cmd == "tekton-plan":
            return tekton_plan(args.base, args.head, args.record_dir, args.result_path)
        if args.cmd == "ci-global":
            return ci_global(args.base, args.head, args.record_dir)
        if args.cmd == "ci-component":
            return ci_component(args.component, args.base, args.head, args.record_dir)
        if args.cmd == "ci-finalize":
            return ci_finalize(args.base, args.head, args.record_dir)
        if args.cmd == "evidence-publish":
            return evidence_publish_command(args.path)
        if args.cmd == "evidence-fetch":
            return evidence_fetch_command(args.sha)
        if args.cmd == "evidence-compare":
            return evidence_compare_command(args.full, args.incremental)
        if args.cmd == "precommit":
            return precommit()
        if args.cmd == "prepush":
            return prepush()
    except MissingRunnerPrerequisite as exc:
        print(f"BLOCKED {exc}", file=sys.stderr)
        return 1
    except (RuntimeError, KeyError, ValueError, json.JSONDecodeError) as exc:
        return fail(str(exc), 1)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
