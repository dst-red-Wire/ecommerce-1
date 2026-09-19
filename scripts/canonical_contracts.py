#!/usr/bin/env python3
"""Generic validator for repository-wide canonical contracts."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
RUBY_LOADER = (
    "require 'yaml'; require 'json'; "
    "d=YAML.safe_load(File.read(ARGV[0]), aliases: false) || {}; "
    "print JSON.generate(d)"
)


class ContractError(RuntimeError):
    pass


def load_yaml(root: Path, relative: str) -> dict:
    path = (root / relative).resolve()
    try:
        path.relative_to(root.resolve())
    except ValueError as exc:
        raise ContractError(f"contract path escapes repository: {relative}") from exc
    if not path.is_file():
        raise ContractError(f"registered contract is missing: {relative}")
    proc = subprocess.run(
        ["ruby", "-e", RUBY_LOADER, str(path)],
        cwd=root,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if proc.returncode:
        raise ContractError(proc.stderr.strip() or f"cannot parse {relative}")
    data = json.loads(proc.stdout or "{}")
    if not isinstance(data, dict):
        raise ContractError(f"contract must be a mapping: {relative}")
    return data


def parse_versions_env(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key, value = key.strip(), value.strip()
        if key in values:
            raise ContractError(f"duplicate version projection key: {key}")
        values[key] = value
    return values


def validate_repository(root: Path = ROOT) -> None:
    lock = load_yaml(root, "architecture.lock.yaml")
    governance = lock.get("repository_governance", {})
    transverse = governance.get("transverse_rule_contract", {})
    if transverse.get("rule_definition") != "central-contract-only":
        raise ContractError("repository transverse rules must be central-contract-only")
    if transverse.get("enforcement") != "generic-validator":
        raise ContractError("repository transverse rules must use the generic validator")

    system = governance.get("canonical_contract_system")
    if not isinstance(system, dict):
        raise ContractError("repository_governance.canonical_contract_system is required")
    if system.get("root_authority") != "architecture.lock.yaml" or system.get("registry") != "machine_contracts":
        raise ContractError("invalid canonical contract root/registry authority")

    registry = lock.get("machine_contracts")
    if not isinstance(registry, dict) or not registry:
        raise ContractError("machine_contracts registry must be a non-empty mapping")
    if any(not isinstance(k,str) or not isinstance(v,str) or not k or not v for k,v in registry.items()):
        raise ContractError("machine_contracts entries must be non-empty string mappings")
    paths=list(registry.values())
    if len(paths)!=len(set(paths)):
        raise ContractError("machine_contracts contains duplicate registered paths")

    actual={
        str(path.relative_to(root))
        for suffix in ("*.yaml","*.yml","*.json")
        for path in (root/"config"/"contracts").glob(suffix)
    }
    registered={path for path in paths if path.startswith("config/contracts/")}
    unregistered=sorted(actual-registered)
    if unregistered:
        raise ContractError("unregistered machine contracts: "+", ".join(unregistered))

    required=system.get("required_contracts",[])
    if not isinstance(required,list) or not required:
        raise ContractError("canonical_contract_system.required_contracts must be non-empty")

    schema_path=registry.get("contract_schema")
    if system.get("schema") != schema_path:
        raise ContractError("canonical_contract_system.schema must reference machine_contracts.contract_schema")
    schema=load_yaml(root,schema_path)
    envelope=schema.get("required_envelope",[])
    statuses=set(schema.get("canonical_statuses",[]))
    if not isinstance(envelope,list) or not envelope:
        raise ContractError("contract schema required_envelope must be non-empty")
    if not statuses:
        raise ContractError("contract schema canonical_statuses must be non-empty")

    architecture_schema=schema.get("architecture_lock")
    if not isinstance(architecture_schema,dict):
        raise ContractError("contract schema must declare architecture_lock")
    root_keys=architecture_schema.get("root_keys")
    section_keys=architecture_schema.get("section_keys")
    if (
        not isinstance(root_keys,list)
        or not root_keys
        or any(not isinstance(key,str) or not key for key in root_keys)
        or len(root_keys)!=len(set(root_keys))
    ):
        raise ContractError("contract schema architecture_lock.root_keys must be unique non-empty strings")
    if not isinstance(section_keys,dict) or not section_keys:
        raise ContractError("contract schema architecture_lock.section_keys must be a non-empty mapping")
    for section,keys in section_keys.items():
        if not isinstance(section,str) or not section:
            raise ContractError("contract schema section names must be non-empty strings")
        if section.split(".",1)[0] not in root_keys:
            raise ContractError(f"contract schema section is outside architecture root: {section}")
        if (
            not isinstance(keys,list)
            or not keys
            or any(not isinstance(key,str) or not key for key in keys)
            or len(keys)!=len(set(keys))
        ):
            raise ContractError(
                f"contract schema section keys must be unique non-empty strings: {section}"
            )

    claims:dict[str,str]={}
    canonical:dict[str,dict]={}
    for key in required:
        relative=registry.get(key)
        if not relative:
            raise ContractError(f"required canonical contract is not registered: {key}")
        data=load_yaml(root,relative)
        canonical[key]=data
        for field in envelope:
            if data.get(field) in (None,"",[]):
                raise ContractError(f"{key}: missing canonical envelope field {field}")
        if data.get("architecture_authority")!="architecture.lock.yaml":
            raise ContractError(f"{key}: architecture authority must be architecture.lock.yaml")
        if data.get("status") not in statuses:
            raise ContractError(f"{key}: unsupported canonical status {data.get('status')!r}")
        if not isinstance(data.get("kind"),str):
            raise ContractError(f"{key}: kind must be a string")
        authority_claims=data.get("authority_claims")
        if not isinstance(authority_claims,list) or not authority_claims:
            raise ContractError(f"{key}: authority_claims must be a non-empty list")
        for claim in authority_claims:
            if not isinstance(claim,str) or not claim:
                raise ContractError(f"{key}: authority claims must be non-empty strings")
            if claim in claims:
                raise ContractError(f"duplicate authority claim {claim}: {claims[claim]} and {key}")
            claims[claim]=key

    for relative in paths:
        load_yaml(root,relative)

    for relative in system.get("forbidden_parallel_authority_files",[]):
        if (root/relative).exists():
            raise ContractError(f"parallel policy authority is forbidden: {relative}")

    toolchain=canonical["toolchain_lock"]
    if toolchain.get("serialization") != "json":
        raise ContractError("toolchain lock serialization must remain json for bootstrap/Ansible consumers")
    try:
        json.loads((root/registry["toolchain_lock"]).read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ContractError("toolchain lock must remain valid JSON despite its .yaml compatibility path") from exc

    vp=toolchain.get("legacy_projections",{}).get("versions_env",{})
    projected=parse_versions_env(root/str(vp.get("path","")))
    expected={str(k):str(v) for k,v in toolchain.get("versions",{}).items()}
    if projected!=expected:
        raise ContractError("config/toolchain/versions.env drifted from canonical toolchain-lock.yaml")

    cp=toolchain.get("legacy_projections",{}).get("capabilities_json",{})
    legacy=json.loads((root/str(cp.get("path",""))).read_text(encoding="utf-8"))
    expected_caps={key:toolchain.get(key) for key in cp.get("keys",[])}
    if legacy!=expected_caps:
        raise ContractError("config/toolchain/capabilities.json drifted from canonical toolchain-lock.yaml")

    for relative in canonical["dependency_lock_policy"].get("required_paths",[]):
        if not (root/relative).is_file():
            raise ContractError(f"required dependency lock is missing: {relative}")

    exceptions=canonical["policy_exceptions"]
    fields=exceptions.get("required_fields",[])
    for entry in exceptions.get("exceptions",[]):
        if not isinstance(entry,dict):
            raise ContractError("policy exception entries must be mappings")
        missing=[field for field in fields if entry.get(field) in (None,"")]
        if missing:
            raise ContractError("policy exception missing fields: "+", ".join(missing))
        expires=str(entry.get("expires",""))
        if not re.fullmatch(r"\d{4}-\d{2}-\d{2}",expires):
            raise ContractError(f"policy exception expiry must be YYYY-MM-DD: {expires!r}")


def main(argv:list[str]|None=None)->int:
    parser=argparse.ArgumentParser()
    parser.add_argument("command",nargs="?",default="validate",choices=("validate","audit-authority"))
    args=parser.parse_args(argv)
    try:
        validate_repository(ROOT)
    except (ContractError,json.JSONDecodeError,OSError) as exc:
        print(f"FAIL canonical contracts: {exc}",file=sys.stderr)
        return 1
    print(f"PASS canonical contracts {args.command}: registry, authority and projections are consistent")
    return 0


if __name__=="__main__":
    raise SystemExit(main())
