#!/usr/bin/env python3
"""Validation statique de la source de vérité governance ecommerce-1."""

from __future__ import annotations

import argparse
import copy
import json
import re
import sys
from collections import Counter
from datetime import date
from pathlib import Path, PurePosixPath
from typing import Any

import yaml
from jsonschema import Draft202012Validator


CONTROL_ID = re.compile(r"^(ARCH|SEC|PRIV|SUPPLY|COMP|IAM|DATA|NET|CRYPTO|SDLC|RES|OBS|IMM|H3)-[0-9]{3}$")
DOC_CONTROL_ID = re.compile(r"\b(?:ARCH|SEC|PRIV|SUPPLY|COMP|IAM|DATA|NET|CRYPTO|SDLC|RES|OBS|IMM|H3)-[0-9]{3}\b")
EXCEPTION_ID = re.compile(r"^EXC-[0-9]{4}$")
ROLES = {"platform", "security", "application", "data", "operations", "privacy"}
CLASSIFICATIONS = {"PUBLIC", "INTERNAL", "CONFIDENTIAL", "RESTRICTED"}
RETENTION_TBD = {
    "TBD_REQUIRES_BUSINESS_OR_LEGAL_APPROVAL",
    "TBD_REQUIRES_BUSINESS_APPROVAL",
}
EXPECTED_RUNTIME_PROOFS = {
    "remote identity": "PROVEN_RUNTIME",
    "volume attachment": "PROVEN_RUNTIME",
    "volume mount": "PROVEN_RUNTIME",
    "PostgreSQL": "PROVEN_RUNTIME",
    "TLS": "PROVEN_RUNTIME",
    "SCRAM": "PROVEN_RUNTIME",
    "PGDATA": "PROVEN_RUNTIME",
    "Ansible idempotence": "PROVEN_RUNTIME",
    "Terraform PG backend": "PROVEN_RUNTIME",
    "Terraform PG locking": "PROVEN_RUNTIME",
    "reboot persistence": "PROVISIONAL_RUNTIME_PASS",
    "HTTP/3 production edge": "NOT_PROVEN_RUNTIME",
    "Management backend": "NOT_MIGRATED",
}
REQUIRED_POLICY_DOCS = (
    "docs/architecture/index.md",
    "docs/architecture/system-context.md",
    "docs/architecture/threat-model.md",
    "docs/architecture/adr-http3-production-edge.md",
    "docs/security/governance.md",
    "docs/security/secure-design-sdlc.md",
    "docs/security/threat-modeling.md",
    "docs/security/threat-model-template.md",
    "docs/security/privacy-data.md",
    "docs/security/supply-chain-policy.md",
    "docs/security/infrastructure-security.md",
    "docs/security/secrets-crypto-network.md",
    "docs/security/vulnerability-dependency.md",
    "docs/security/resilience-evidence-operations.md",
    "docs/security/exception-policy.md",
)


def load_yaml(path: Path) -> Any:
    with path.open(encoding="utf-8") as stream:
        return yaml.safe_load(stream)


def load_json(path: Path) -> Any:
    with path.open(encoding="utf-8") as stream:
        return json.load(stream)


def schema_errors(instance: Any, schema: Any, label: str) -> list[str]:
    validator = Draft202012Validator(schema)
    return [
        f"{label}:{'/'.join(str(item) for item in error.absolute_path) or '<root>'}: {error.message}"
        for error in sorted(validator.iter_errors(instance), key=lambda item: list(item.absolute_path))
    ]


def validate_evidence_path(root: Path, evidence: dict[str, Any], context: str) -> list[str]:
    errors: list[str] = []
    value = evidence.get("path")
    if value is None:
        return errors
    if not isinstance(value, str) or "\\" in value:
        return [f"{context}: evidence path must be a POSIX repository-relative path"]
    path = PurePosixPath(value)
    if path.is_absolute() or ".." in path.parts or not path.parts:
        errors.append(f"{context}: unsafe evidence path: {value}")
    elif not (root / Path(*path.parts)).exists():
        errors.append(f"{context}: evidence path does not exist: {value}")
    return errors


def validate_data_policy(data_policy: Any) -> list[str]:
    errors: list[str] = []
    if not isinstance(data_policy, dict) or data_policy.get("schema_version") != 1:
        return ["data-policy.yaml: schema_version must be 1"]
    classes = data_policy.get("classifications")
    if not isinstance(classes, list):
        return ["data-policy.yaml: classifications must be a list"]
    ids = [item.get("id") for item in classes if isinstance(item, dict)]
    if set(ids) != CLASSIFICATIONS or len(ids) != len(CLASSIFICATIONS):
        errors.append("data-policy.yaml: classifications must define PUBLIC, INTERNAL, CONFIDENTIAL and RESTRICTED exactly once")
    for key in ("pii", "credentials", "authentication_tokens", "psp_tokens", "cardholder_data"):
        if data_policy.get("classification_rules", {}).get(key) != "RESTRICTED":
            errors.append(f"data-policy.yaml: {key} must be RESTRICTED")
    for index, rule in enumerate(data_policy.get("retention_rules", [])):
        context = f"data-policy.yaml:retention_rules[{index}]"
        if rule.get("classification") not in CLASSIFICATIONS:
            errors.append(f"{context}: unknown classification")
        if rule.get("owner_role") not in ROLES:
            errors.append(f"{context}: owner_role is mandatory and role-based")
        retention = rule.get("retention_status")
        if not isinstance(retention, str) or (not retention.strip()):
            errors.append(f"{context}: retention_status is mandatory")
        elif retention.startswith("TBD_") and retention not in RETENTION_TBD:
            errors.append(f"{context}: unsupported explicit TBD retention status")
    processor_inventory = data_policy.get("third_party_processors", {})
    if processor_inventory.get("inventory_status") not in RETENTION_TBD:
        errors.append("data-policy.yaml: third-party processor inventory status must be explicit")
    if not isinstance(processor_inventory.get("entries"), list):
        errors.append("data-policy.yaml: third-party processor entries must be a list")
    return errors


def validate_model(
    root: Path,
    controls: Any,
    frameworks: Any,
    environments: Any,
    exceptions: Any,
    data_policy: Any,
    schema: Any,
    today: date | None = None,
) -> list[str]:
    errors = schema_errors(controls, schema, "controls.yaml")
    if errors:
        return errors

    current_date = today or date.today()
    control_items = controls["controls"]
    control_ids = [item["id"] for item in control_items]
    duplicates = sorted(item for item, count in Counter(control_ids).items() if count > 1)
    if duplicates:
        errors.append(f"controls.yaml: duplicate control IDs: {', '.join(duplicates)}")
    known_controls = set(control_ids)

    framework_items = frameworks.get("frameworks", []) if isinstance(frameworks, dict) else []
    framework_ids = [item.get("id") for item in framework_items if isinstance(item, dict)]
    if len(framework_ids) != len(set(framework_ids)):
        errors.append("frameworks.yaml: framework IDs must be unique")
    known_frameworks = set(framework_ids)
    baseline = {item.get("id"): item for item in framework_items if isinstance(item, dict)}
    if baseline.get("NIST_SSDF_1_1", {}).get("status") != "FINAL":
        errors.append("frameworks.yaml: NIST SSDF 1.1 must remain the FINAL baseline")
    if baseline.get("NIST_SSDF_1_2_DRAFT", {}).get("status") != "DRAFT":
        errors.append("frameworks.yaml: NIST SSDF 1.2 must remain DRAFT")
    if baseline.get("SLSA_1_2", {}).get("status") != "APPROVED":
        errors.append("frameworks.yaml: SLSA 1.2 must remain APPROVED")
    if baseline.get("OWASP_ASVS_5_0_0", {}).get("status") != "STABLE":
        errors.append("frameworks.yaml: OWASP ASVS 5.0.0 must remain STABLE")
    for item in framework_items:
        if item.get("claim_allowed") is not False:
            errors.append(f"frameworks.yaml:{item.get('id')}: claim_allowed must be false")

    environment_items = environments.get("environments", []) if isinstance(environments, dict) else []
    environment_ids = [item.get("id") for item in environment_items if isinstance(item, dict)]
    if len(environment_ids) != len(set(environment_ids)):
        errors.append("environments.yaml: environment IDs must be unique")
    known_environments = set(environment_ids)

    for control in control_items:
        control_id = control["id"]
        if not CONTROL_ID.fullmatch(control_id):
            errors.append(f"controls.yaml:{control_id}: invalid control ID")
        unknown_environments = set(control["environments"]) - known_environments
        if unknown_environments:
            errors.append(f"controls.yaml:{control_id}: unknown environments: {sorted(unknown_environments)}")
        for index, mapping in enumerate(control["framework_mappings"]):
            context = f"controls.yaml:{control_id}:framework_mappings[{index}]"
            if mapping["framework"] not in known_frameworks:
                errors.append(f"{context}: unknown framework: {mapping['framework']}")
            external_control = mapping.get("control")
            if not isinstance(external_control, str) or not external_control.strip() or "???" in external_control:
                errors.append(f"{context}: malformed framework control reference")
            project_control = mapping.get("project_control_id")
            if project_control is not None and project_control not in known_controls:
                errors.append(f"{context}: nonexistent project control mapping: {project_control}")
            elif project_control is not None and project_control != control_id:
                errors.append(f"{context}: project_control_id must match containing control {control_id}")
        for index, evidence in enumerate(control["evidence"]):
            errors.extend(validate_evidence_path(root, evidence, f"controls.yaml:{control_id}:evidence[{index}]"))
        if control["runtime_status"] == "PROVEN_RUNTIME":
            proven = any(
                item["type"] == "runtime_probe" and item["status"] in {"AVAILABLE", "EXTERNAL_REVIEWED"}
                for item in control["evidence"]
            )
            if not proven:
                errors.append(f"controls.yaml:{control_id}: PROVEN_RUNTIME requires runtime probe evidence")

    proof_items = controls["runtime_proofs"]
    proof_map = {item["capability"]: item["status"] for item in proof_items}
    if len(proof_map) != len(proof_items):
        errors.append("controls.yaml: runtime proof capabilities must be unique")
    if proof_map != EXPECTED_RUNTIME_PROOFS:
        errors.append("controls.yaml: current runtime proof matrix changed or is incomplete")
    for proof in proof_items:
        for index, evidence in enumerate(proof["evidence"]):
            errors.extend(validate_evidence_path(root, evidence, f"runtime_proofs:{proof['capability']}:evidence[{index}]"))
        if proof["status"] == "PROVEN_RUNTIME":
            proven = any(
                item["type"] == "runtime_probe" and item["status"] in {"AVAILABLE", "EXTERNAL_REVIEWED"}
                for item in proof["evidence"]
            )
            if not proven:
                errors.append(f"runtime_proofs:{proof['capability']}: PROVEN_RUNTIME requires evidence")

    architecture = controls["architecture_requirements"]
    if architecture["H3_REQUIRED_FOR_PRODUCTION_EDGE"] is not True:
        errors.append("controls.yaml: H3_REQUIRED_FOR_PRODUCTION_EDGE must be true")
    if architecture["HTTP2_FALLBACK_REQUIRED"] is not True:
        errors.append("controls.yaml: HTTP2_FALLBACK_REQUIRED must be true")
    if architecture["ZERO_RTT_POLICY"] != "DISABLED_BY_DEFAULT":
        errors.append("controls.yaml: ZERO_RTT_POLICY must be DISABLED_BY_DEFAULT")

    if not isinstance(exceptions, dict) or exceptions.get("schema_version") != 1:
        errors.append("exceptions.yaml: schema_version must be 1")
    exception_policy = exceptions.get("policy", {}) if isinstance(exceptions, dict) else {}
    if exception_policy != {
        "permanent_exceptions_allowed": False,
        "wildcard_scope_allowed": False,
        "expiry_required": True,
        "expired_exception_action": "FAIL",
    }:
        errors.append("exceptions.yaml: exception policy must remain fail-closed")
    exception_ids: set[str] = set()
    for index, exception in enumerate(exceptions.get("exceptions", [])):
        context = f"exceptions.yaml:exceptions[{index}]"
        required = {
            "id", "control_id", "reason", "risk", "compensating_controls", "scope",
            "environments", "approver_role", "reference", "created_at", "expires_at",
        }
        missing = sorted(required - set(exception))
        if missing:
            errors.append(f"{context}: missing required fields: {', '.join(missing)}")
            continue
        exception_id = exception["id"]
        if not isinstance(exception_id, str) or not EXCEPTION_ID.fullmatch(exception_id):
            errors.append(f"{context}: invalid exception ID")
        elif exception_id in exception_ids:
            errors.append(f"{context}: duplicate exception ID: {exception_id}")
        exception_ids.add(exception_id)
        control_id = exception["control_id"]
        if control_id not in known_controls:
            errors.append(f"{context}: nonexistent control reference: {control_id}")
        else:
            control = next(item for item in control_items if item["id"] == control_id)
            if not control["exception_allowed"]:
                errors.append(f"{context}: control {control_id} forbids exceptions")
        for field in ("reason", "risk", "reference"):
            if not isinstance(exception[field], str) or not exception[field].strip():
                errors.append(f"{context}: {field} must be non-empty")
        compensating = exception["compensating_controls"]
        if not isinstance(compensating, list) or not compensating or any(not str(value).strip() for value in compensating):
            errors.append(f"{context}: compensating_controls must be a non-empty list")
        scope = exception["scope"]
        if not isinstance(scope, dict) or not scope:
            errors.append(f"{context}: scope must be a non-empty object")
        elif any(value == "*" or (isinstance(value, list) and "*" in value) for value in scope.values()):
            errors.append(f"{context}: wildcard scope is forbidden")
        if exception["approver_role"] not in ROLES:
            errors.append(f"{context}: approver_role must be a known role")
        unknown = set(exception["environments"]) - known_environments if isinstance(exception["environments"], list) else {"<invalid>"}
        if unknown:
            errors.append(f"{context}: unknown environments: {sorted(unknown)}")
        try:
            created_at = date.fromisoformat(str(exception["created_at"]))
            expires_at = date.fromisoformat(str(exception["expires_at"]))
            if expires_at <= created_at:
                errors.append(f"{context}: expires_at must be after created_at")
            if expires_at < current_date:
                errors.append(f"{context}: exception expired on {expires_at.isoformat()}")
        except ValueError:
            errors.append(f"{context}: created_at and expires_at must be ISO dates")

    errors.extend(validate_data_policy(data_policy))
    return errors


def validate_documentation(root: Path, controls: Any) -> list[str]:
    errors: list[str] = []
    known_controls = {item["id"] for item in controls["controls"]}
    for relative in REQUIRED_POLICY_DOCS:
        path = root / relative
        if not path.is_file():
            errors.append(f"documentation: required file missing: {relative}")
            continue
        text = path.read_text(encoding="utf-8")
        if "governance/controls.yaml" not in text:
            errors.append(f"documentation:{relative}: canonical controls.yaml link is missing")
        unknown = sorted(set(DOC_CONTROL_ID.findall(text)) - known_controls)
        if unknown:
            errors.append(f"documentation:{relative}: unknown control IDs: {', '.join(unknown)}")

    architecture_index = root / "docs/architecture/index.md"
    if architecture_index.is_file():
        text = architecture_index.read_text(encoding="utf-8")
        for capability, status in EXPECTED_RUNTIME_PROOFS.items():
            expected_row = f"| {capability} | `{status}` |"
            if expected_row not in text:
                errors.append(f"documentation: runtime matrix row missing or contradictory: {capability}={status}")

    scan_paths = [root / "docs/security", root / "docs/architecture"]
    forbidden = re.compile(
        r"ecommerce-1\s+(?:is|est)\s+(?:ISO(?:/IEC)?\s*27001|SOC\s*2|GDPR|RGPD|PCI\s*DSS|NIST|SLSA\s*L3)\s+(?:compliant|conforme)",
        re.IGNORECASE,
    )
    for directory in scan_paths:
        for path in directory.glob("*.md"):
            if forbidden.search(path.read_text(encoding="utf-8")):
                errors.append(f"documentation:{path.relative_to(root).as_posix()}: forbidden compliance claim")
    return errors


def validate_repository(root: Path, today: date | None = None) -> tuple[list[str], Any]:
    controls = load_yaml(root / "governance/controls.yaml")
    errors = validate_model(
        root,
        controls,
        load_yaml(root / "governance/frameworks.yaml"),
        load_yaml(root / "governance/environments.yaml"),
        load_yaml(root / "governance/exceptions.yaml"),
        load_yaml(root / "governance/data-policy.yaml"),
        load_json(root / "governance/controls.schema.json"),
        today=today,
    )
    errors.extend(validate_documentation(root, controls))
    return errors, controls


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parent.parent)
    parser.add_argument("--json", action="store_true", help="Émettre un résumé JSON sans données sensibles")
    args = parser.parse_args()
    root = args.root.resolve()
    errors, controls = validate_repository(root)
    if errors:
        for error in errors:
            print(f"[governance] ERROR: {error}", file=sys.stderr)
        return 1
    counts = dict(sorted(Counter(item["category"] for item in controls["controls"]).items()))
    summary = {"status": "PASS", "control_count": len(controls["controls"]), "categories": counts}
    if args.json:
        print(json.dumps(summary, ensure_ascii=False, sort_keys=True))
    else:
        print(f"[governance] PASS: {summary['control_count']} controls; categories={counts}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
