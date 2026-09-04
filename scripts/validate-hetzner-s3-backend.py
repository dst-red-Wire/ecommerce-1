#!/usr/bin/env python3
"""Guard Hetzner S3 as archive/diagnostic only, never management backend."""

from __future__ import annotations

import json
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CANONICAL = ROOT / "infrastructure/hetzner/backend/hetzner-s3.common.tfbackend"
MANAGEMENT_BACKEND = ROOT / "infrastructure/hetzner/management/backend.tf"
MANAGEMENT_CONTRACT = ROOT / "infrastructure/hetzner/management/backend.contract.json"
PROBE_BACKEND = ROOT / (
    "infrastructure/hetzner/bootstrap/object-storage/lock-runtime-test/backend.tf"
)
INITIALIZER = ROOT / "scripts/init-hetzner-s3-backend.sh"
LOCK_HARNESS = ROOT / "scripts/test-hetzner-s3-locking.sh"
POLICY_TEMPLATE = ROOT / (
    "infrastructure/hetzner/bootstrap/object-storage/"
    "management-bucket-policy.json.tftpl"
)
BOOTSTRAP_MAIN = ROOT / "infrastructure/hetzner/bootstrap/object-storage/main.tf"
RUNTIME_GATES = ROOT / (
    "infrastructure/hetzner/bootstrap/object-storage/runtime-gates.tf"
)
LOCAL_STATE_HELPER = ROOT / "scripts/bootstrap-local-state.sh"
OBJECT_STORAGE_WRAPPER = ROOT / "scripts/object-storage-bootstrap-state.sh"


def fail(message: str) -> None:
    raise SystemExit(f"Hetzner S3 archive contract invalid: {message}")


def read(path: Path) -> str:
    if not path.is_file():
        fail(f"required file is missing: {path.relative_to(ROOT)}")
    return path.read_text(encoding="utf-8")


def require_assignment(content: str, name: str, value_pattern: str, source: str) -> None:
    pattern = rf"(?m)^\s*{re.escape(name)}\s*=\s*{value_pattern}\s*$"
    if not re.search(pattern, content):
        fail(f"{source} must set {name} to the canonical value")


canonical = read(CANONICAL)
required_canonical = {
    "region": r'"nbg1"',
    "acl": r'"private"',
    "use_path_style": r"false",
    "skip_credentials_validation": r"true",
    "skip_metadata_api_check": r"true",
    "skip_region_validation": r"true",
    "skip_requesting_account_id": r"true",
}
for attribute, expected in required_canonical.items():
    require_assignment(canonical, attribute, expected, str(CANONICAL.relative_to(ROOT)))
if 's3 = "https://nbg1.your-objectstorage.com"' not in canonical:
    fail("canonical diagnostic endpoint is missing or incorrect")
for forbidden in ("access_key", "secret_key", "token"):
    if re.search(rf"(?m)^\s*{forbidden}\s*=", canonical):
        fail(f"canonical diagnostic config must not set {forbidden}")

management_backend = read(MANAGEMENT_BACKEND)
if not re.search(r'backend\s+"pg"\s*\{', management_backend):
    fail("management must use backend pg")
if re.search(r'backend\s+"s3"\s*\{', management_backend):
    fail("management must not contain an active S3 backend")
for forbidden in ("your-objectstorage.com", "use_lockfile", "access_key", "secret_key"):
    if forbidden in management_backend:
        fail(f"management backend contains forbidden S3/secret token {forbidden!r}")

probe_backend = read(PROBE_BACKEND)
match = re.search(r'backend\s+"s3"\s*\{(?P<body>.*?)\n\s*\}', probe_backend, re.DOTALL)
if not match:
    fail("retained diagnostic root must keep its S3 backend")
probe_body = match.group("body")
require_assignment(
    probe_body,
    "key",
    re.escape(json.dumps("ecommerce/lock-tests/terraform.tfstate")),
    "lock diagnostic",
)
require_assignment(probe_body, "use_lockfile", "true", "lock diagnostic")
assignments = set(re.findall(r"(?m)^\s*([a-zA-Z0-9_]+)\s*=", probe_body))
if assignments != {"key", "use_lockfile"}:
    fail("diagnostic backend must differ from canonical config only by key/use_lockfile")

contract = json.loads(read(MANAGEMENT_CONTRACT))
if contract.get("backendType") != "pg":
    fail("management contract backendType must be pg")
decision = contract.get("architectureDecision", {})
if decision.get("aws") != "NOT_SELECTED":
    fail("AWS must be explicitly NOT_SELECTED")
if decision.get("hetznerObjectStorageBackend") != "INCOMPATIBLE":
    fail("Hetzner Object Storage backend must be INCOMPATIBLE")
archive = contract.get("objectStorage", {})
if archive != {
    "bucket": "ecommerce-management-tfstate-20260820-70b94831",
    "authoritativeStateLocking": False,
    "lockingStatus": "INCOMPATIBLE",
    "role": "encrypted-backup-and-evidence-archive",
}:
    fail("preserved bucket must be archive-only and non-authoritative")

initializer = read(INITIALIZER)
for guard in (
    'usage: $0 lock-runtime-test',
    "Hetzner S3 is INCOMPATIBLE as the management backend",
    "root=infrastructure/hetzner/bootstrap/object-storage/lock-runtime-test",
):
    if guard not in initializer:
        fail(f"S3 initializer is missing management rejection guard: {guard}")
if "root=infrastructure/hetzner/management" in initializer:
    fail("S3 initializer must have no management activation path")

lock_harness = read(LOCK_HARNESS)
for proof in (
    "s3_get_lock",
    "holderLockObservedViaAuthenticatedGet: true",
    "conditionalWriteViolated: true",
    'status: "INCOMPATIBLE"',
    "S3 native locking is INCOMPATIBLE",
):
    if proof not in lock_harness:
        fail(f"retained S3 diagnostic is missing proof token: {proof}")
if "-lock=false" in lock_harness:
    fail("retained S3 diagnostic must never disable locking")

policy_source = read(POLICY_TEMPLATE)
policy = json.loads(
    policy_source.replace("${bucket_name}", "preserved-bucket").replace(
        "${management_principal}",
        "arn:aws:iam:::user/p1234567:REPLACEARCHIVEKEY",
    )
)
statements = policy.get("Statement", [])
if len(statements) != 4:
    fail("archive policy must contain exactly four reviewed statements")
principals = {statement.get("Principal", {}).get("AWS") for statement in statements}
if principals != {"arn:aws:iam:::user/p1234567:REPLACEARCHIVEKEY"}:
    fail("archive policy must allow exactly one explicit principal")
if any("*" in str(principal) for principal in principals):
    fail("archive policy must not contain a wildcard principal")

by_sid = {statement.get("Sid"): statement for statement in statements}
expected_sids = {
    "ListTerraformBackupArchiveBucket",
    "ReadLegacyManagementStateObject",
    "ReadWriteLockDiagnosticObjects",
    "ReadWriteEncryptedBackupAndEvidenceArchives",
}
if set(by_sid) != expected_sids:
    fail("archive policy statement IDs differ from the reviewed boundary")

legacy = by_sid["ReadLegacyManagementStateObject"]
if set(legacy["Action"]) != {"s3:GetObject", "s3:GetObjectVersion"}:
    fail("legacy management state must be read-only")
if "s3:PutObject" in json.dumps(legacy):
    fail("legacy management state must not be writable")

archive_statement = by_sid["ReadWriteEncryptedBackupAndEvidenceArchives"]
archive_resources = set(archive_statement["Resource"])
expected_archive_resources = {
    "arn:aws:s3:::preserved-bucket/ecommerce/backups/postgresql/*",
    "arn:aws:s3:::preserved-bucket/ecommerce/backups/bootstrap-terraform-state/*",
    "arn:aws:s3:::preserved-bucket/ecommerce/evidence/*",
}
if archive_resources != expected_archive_resources:
    fail("encrypted backup/evidence prefixes differ from the reviewed contract")
if "s3:DeleteObject" in archive_statement["Action"]:
    fail("ordinary archive credentials must not delete versioned backups")

bootstrap_main = read(BOOTSTRAP_MAIN)
runtime_gates = read(RUNTIME_GATES)
for source_name, source in (("bootstrap", bootstrap_main), ("runtime gate", runtime_gates)):
    if "management-bucket-policy.json.tftpl" not in source:
        fail(f"{source_name} must consume the canonical archive policy template")
    if "management_principal_arn" not in source:
        fail(f"{source_name} must bind the explicit archive principal")
if 'resource "minio_s3_bucket_policy" "terraform_state"' not in bootstrap_main:
    fail("bootstrap must manage the archive policy declaratively")
if "prevent_destroy = true" not in bootstrap_main:
    fail("bucket and policy resources must retain prevent_destroy")

state_helper = read(LOCAL_STATE_HELPER)
wrapper = read(OBJECT_STORAGE_WRAPPER)
for guard in (
    "bootstrap plan requires -out=<absolute-path>",
    "bootstrap plan must remain outside the authoritative state directory",
    "bootstrap plan output must remain outside the repository and OneDrive",
    "bootstrap apply accepts exactly one reviewed saved plan",
    "caller-supplied Terraform state or backup path options are forbidden",
):
    if guard not in state_helper:
        fail(f"shared local-state helper is missing gate: {guard}")
if "BOOTSTRAP_STATE_SLUG=bootstrap-object-storage" not in wrapper:
    fail("object-storage wrapper must retain an independent local state namespace")

print("Hetzner S3 archive/diagnostic contract: valid (locking INCOMPATIBLE)")
