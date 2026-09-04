#!/usr/bin/env python3
"""Validate the PostgreSQL Terraform backend foundation without remote access."""

from __future__ import annotations

import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def fail(message: str) -> None:
    raise SystemExit(f"Terraform pg backend foundation invalid: {message}")


def read(relative: str) -> str:
    path = ROOT / relative
    if not path.is_file():
        fail(f"required file is missing: {relative}")
    return path.read_text(encoding="utf-8")


def require(content: str, tokens: tuple[str, ...], source: str) -> None:
    for token in tokens:
        if token not in content:
            fail(f"{source} is missing {token!r}")


env_example = read(".env.example")
expected_project_keys = {
    "TERRAFORM_STATE_POSTGRESQL_PASSWORD",
    "TERRAFORM_STATE_BACKUP_AGE_IDENTITY",
    "TERRAFORM_STATE_BACKUP_AGE_RECIPIENT",
}
documented_project_keys: set[str] = set()
for line_number, line in enumerate(env_example.splitlines(), start=1):
    if not line.strip() or line.lstrip().startswith("#"):
        continue
    if "=" not in line:
        fail(f".env.example has a malformed assignment on line {line_number}")
    key, value = line.split("=", 1)
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", key):
        fail(f".env.example has an invalid key on line {line_number}")
    if key in documented_project_keys:
        fail(f".env.example duplicates {key}")
    if value:
        fail(f".env.example must not contain a value for {key}")
    documented_project_keys.add(key)
if not expected_project_keys.issubset(documented_project_keys):
    fail(".env.example does not document the initial project secret contract")

loader = read("scripts/run-with-project-env.py")
require(
    loader,
    (
        'PROJECT_ENV_PARTS = (".config", "ecommerce-1", ".env")',
        "pwd.getpwuid(os.geteuid()).pw_dir",
        'Path("/mnt/c")',
        'Path("/tmp")',
        'startswith("onedrive")',
        'getattr(os, "O_NOFOLLOW", 0)',
        "stat.S_ISREG",
        "file_status.st_uid != os.geteuid()",
        "file_mode & ~0o600",
        "parent_mode & ~0o700",
        "duplicate variable key",
        "invalid variable key",
        "age-keygen",
        '[age_keygen, "-y"]',
        "derived_recipient != recipient",
        "os.execvpe",
    ),
    "project environment loader",
)
for forbidden_loader_token in ("eval(", "shell=True", "source .env"):
    if forbidden_loader_token in loader:
        fail(f"project environment loader contains {forbidden_loader_token!r}")

secret_helper = read("scripts/init-project-secrets.sh")
require(
    secret_helper,
    (
        ".config/ecommerce-1",
        "chmod 0700",
        "chmod 0600",
        "--force",
        "secrets.token_urlsafe(48)",
        "age-keygen",
        "age-keygen -y",
        "os.replace",
        "os.link",
        "run-with-project-env.py",
    ),
    "project secret generation helper",
)

project_env_tests = read("tests/terraform-pg/test_project_env.py")
require(
    project_env_tests,
    (
        "test_secure_file_comments_blank_lines_and_expected_variables_pass",
        "test_missing_file_symlink_and_open_permissions_fail",
        "test_wrong_owner_fails_when_testable",
        "test_duplicate_invalid_and_malformed_assignments_fail",
        "test_shell_like_value_is_data_and_is_never_executed",
        "test_required_values_length_match_and_placeholders_fail",
        "test_helper_syntax_and_human_gate_contract",
    ),
    "project environment tests",
)

ignore = read(".gitignore")
require(ignore, (".env", ".env.*", "!.env.example"), ".gitignore")
if "infrastructure/ansible/group_vars/terraform_state_bootstrap/secrets.yml" in ignore:
    fail(".gitignore still preserves the retired terraform-state Vault mechanism")

tracked_result = subprocess.run(
    ["git", "ls-files", "-z"],
    cwd=ROOT,
    capture_output=True,
    check=False,
)
if tracked_result.returncode != 0:
    fail("cannot inspect tracked files for the project secret contract")
tracked_paths = {
    Path(raw_path.decode("utf-8"))
    for raw_path in tracked_result.stdout.split(b"\0")
    if raw_path
}
for tracked_path in tracked_paths:
    if tracked_path.name == ".env" or (
        tracked_path.name.startswith(".env.")
        and tracked_path.name != ".env.example"
    ):
        fail(f"real environment file is tracked: {tracked_path.as_posix()}")
if Path("infrastructure/ansible/group_vars/terraform_state_bootstrap/secrets.yml") in tracked_paths:
    fail("retired terraform-state secrets.yml is tracked")

ignore_real_env = subprocess.run(
    ["git", "check-ignore", "--quiet", "--no-index", ".env"],
    cwd=ROOT,
    check=False,
)
if ignore_real_env.returncode != 0:
    fail(".gitignore does not protect the root .env")
ignore_example = subprocess.run(
    ["git", "check-ignore", "--quiet", "--no-index", ".env.example"],
    cwd=ROOT,
    check=False,
)
if ignore_example.returncode == 0:
    fail(".env.example is ignored and cannot remain versionable")
if (ROOT / ".env").exists() or (ROOT / ".env").is_symlink():
    fail("a real .env exists inside the repository")

retired_secret_file = ROOT / "infrastructure/ansible/group_vars/terraform_state_bootstrap/secrets.yml"
if retired_secret_file.exists() or retired_secret_file.is_symlink():
    fail("retired terraform-state secrets.yml still exists")
if (ROOT / "infrastructure/ansible/examples/terraform-state-secrets.example.yml").exists():
    fail("retired terraform-state Vault example still exists")

management_backend = read("infrastructure/hetzner/management/backend.tf")
if len(re.findall(r'backend\s+"pg"\s*\{', management_backend)) != 1:
    fail("management must declare exactly one pg backend")
if re.search(r'backend\s+"s3"\s*\{', management_backend):
    fail("management contains an active S3 backend")
require(
    management_backend,
    (
        'schema_name          = "terraform_management"',
        "skip_schema_creation = true",
        "skip_table_creation  = true",
        "skip_index_creation  = true",
        "PG_CONN_STR",
        "PGPASSWORD",
    ),
    "management/backend.tf",
)
for forbidden in (
    "conn_str =",
    "password =",
    "your-objectstorage.com",
    "use_lockfile",
):
    if forbidden in management_backend:
        fail(f"management backend contains forbidden token {forbidden!r}")

management_contract = json.loads(
    read("infrastructure/hetzner/management/backend.contract.json")
)
if management_contract.get("version") != 4:
    fail("management pg backend contract must use version 4")
expected_contract = {
    "backendType": "pg",
    "database": "terraform_backend",
    "schemaName": "terraform_management",
    "tableName": "states",
    "workspace": "default",
    "nonDefaultWorkspacesForbidden": True,
    "terraformVersion": "1.15.5",
    "schemaObjectsPrecreatedByAnsible": True,
    "skipSchemaCreation": True,
    "skipTableCreation": True,
    "skipIndexCreation": True,
    "localStateFallbackForbidden": True,
}
for field, expected in expected_contract.items():
    if management_contract.get(field) != expected:
        fail(f"management contract field {field} must equal {expected!r}")
if management_contract.get("locking", {}).get("runtimeStatus") != "NOT_PROVEN_RUNTIME":
    fail("PostgreSQL locking must remain NOT_PROVEN_RUNTIME before live proof")
if management_contract.get("locking", {}).get("mechanism") != "postgresql-advisory-locks":
    fail("management locking mechanism must be PostgreSQL advisory locks")
if management_contract.get("tls", {}).get("sslmode") != "verify-full":
    fail("management backend must require sslmode=verify-full")
credentials_contract = management_contract.get("credentials", {})
if credentials_contract.get("allowedConnectionUrlFields") != [
    "scheme",
    "user",
    "host",
    "port",
    "database",
    "sslmode",
]:
    fail("PG connection URL fields differ from the canonical contract")
if not credentials_contract.get("unknownOrDuplicateParametersForbidden"):
    fail("unknown and duplicate PG connection parameters must be forbidden")
if not credentials_contract.get("competingPostgresqlEnvironmentForbidden"):
    fail("competing PostgreSQL environment variables must be forbidden")
if not management_contract.get("tls", {}).get("wrongCaRejectionRequired"):
    fail("wrong-CA TLS rejection proof must be required")
if not management_contract.get("tls", {}).get("wrongHostnameRejectionRequired"):
    fail("wrong-hostname TLS rejection proof must be required")
boundary = management_contract.get("postgresqlBoundary", {})
if boundary.get("server") != "terraform-state-mgmt":
    fail("backend server must be terraform-state-mgmt")
if not boundary.get("dataMgmtReuseForbidden"):
    fail("data-mgmt reuse must be forbidden")
if set(boundary.get("allowedSchemas", [])) != {
    "terraform_management",
    "terraform_lock_probe",
}:
    fail("PostgreSQL schema boundary differs from the reviewed design")
activation_contract = management_contract.get("stateActivation", {})
for required_true in (
    "completeLegacyVersionHistoryRequired",
    "deleteMarkersInspected",
    "unknownHistoryForbidsInitialization",
    "postgresqlTargetEmptyPreflightRequired",
    "postgresqlTargetPostInitValidationRequired",
    "operatorWriterFreezeRequired",
):
    if activation_contract.get(required_true) is not True:
        fail(f"state activation contract must require {required_true}")

bootstrap_main = read("infrastructure/hetzner/bootstrap/terraform-state/main.tf")
bootstrap_variables = read(
    "infrastructure/hetzner/bootstrap/terraform-state/variables.tf"
)
bootstrap_outputs = read("infrastructure/hetzner/bootstrap/terraform-state/outputs.tf")
bootstrap_versions = read("infrastructure/hetzner/bootstrap/terraform-state/versions.tf")
bootstrap_contract = json.loads(
    read("infrastructure/hetzner/bootstrap/terraform-state/backend.contract.json")
)
require(
    bootstrap_main,
    (
        'resource "hcloud_server" "terraform_state"',
        'name        = "terraform-state-mgmt"',
        'resource "hcloud_firewall" "terraform_state"',
        'port        = "22"',
        "source_ips  = var.ssh_allowed_cidrs",
        "ipv4_enabled = true",
        "ipv6_enabled = false",
        "delete_protection  = true",
        "rebuild_protection = true",
        'resource "hcloud_volume" "postgresql"',
        "delete_protection = true",
        "prevent_destroy = true",
        'format            = "ext4"',
        'resource "hcloud_volume_attachment" "postgresql"',
        "automount = false",
    ),
    "bootstrap/terraform-state/main.tf",
)
if re.search(r'port\s*=\s*"5432"', bootstrap_main):
    fail("bootstrap Hetzner firewall exposes PostgreSQL 5432")
for forbidden_dependency in (
    "gitea-mgmt",
    "harbor-mgmt",
    "data-mgmt",
    "hcloud_network.management",
):
    if forbidden_dependency in bootstrap_main:
        fail(f"bootstrap root depends on {forbidden_dependency}")
require(
    bootstrap_variables,
    (
        'default     = "nbg1"',
        'default     = "cx23"',
        'default     = "ubuntu-24.04"',
        "default     = 10",
        'cidr != "0.0.0.0/0"',
        ">= 24",
    ),
    "bootstrap/terraform-state/variables.tf",
)
require(
    bootstrap_versions,
    ('required_version = "= 1.15.5"', 'version = "~> 1.68.0"'),
    "bootstrap/terraform-state/versions.tf",
)
require(
    bootstrap_outputs,
    (
        "inventory_contract",
        "server_id                   = hcloud_server.terraform_state.id",
        "server_name                 = hcloud_server.terraform_state.name",
        "server_ipv4                 = hcloud_server.terraform_state.ipv4_address",
        'postgresql_bind_address     = "127.0.0.1"',
        "public_postgresql_exposed   = false",
        "management_plane_dependency = false",
        "cost_review_contract",
    ),
    "bootstrap/terraform-state/outputs.tf",
)
if bootstrap_contract.get("bootstrapState", {}).get("backendType") != "local":
    fail("bootstrap state must stay local and independent")
bootstrap_state = bootstrap_contract["bootstrapState"]
for required_true in (
    "repositoryLocationForbidden",
    "oneDriveLocationForbidden",
    "hashRequired",
    "lineageRequired",
    "serialRequired",
    "encryptedBackupRequired",
    "restoreTestRequired",
):
    if bootstrap_state.get(required_true) is not True:
        fail(f"bootstrap state contract must require {required_true}")
if bootstrap_contract.get("paidApplyStatus") != "NOT_EXECUTED":
    fail("bootstrap paid apply status must remain NOT_EXECUTED")
identity_binding = bootstrap_contract.get("identityBinding", {})
for required_true in (
    "serverIdRequired",
    "serverNameRequired",
    "serverIpv4Required",
    "volumeIdRequired",
    "volumeByIdDerivedFromVolumeId",
    "hetznerMetadataPreMutationGateRequired",
    "dedicatedKnownHostsRequired",
    "independentSshFingerprintRequired",
):
    if identity_binding.get(required_true) is not True:
        fail(f"bootstrap identity binding must require {required_true}")
if identity_binding.get("runtimeStatus") != "NOT_PROVEN_RUNTIME":
    fail("remote identity must remain NOT_PROVEN_RUNTIME before live proof")

playbook = read("infrastructure/ansible/terraform-state.yml")
terraform_state_vars = read(
    "infrastructure/ansible/group_vars/terraform_state_bootstrap/vars.yml"
)
require(
    playbook,
    (
        "hosts: terraform_state_bootstrap",
        "role: terraform_state_base",
        "role: terraform_state_firewall",
        "role: terraform_state_postgresql",
        "169.254.169.254/hetzner/v1/metadata/instance-id",
        "169.254.169.254/hetzner/v1/metadata/hostname",
        "169.254.169.254/hetzner/v1/metadata/public-ipv4",
        "Prove remote Hetzner and volume identity before any mutation",
        "StrictHostKeyChecking=yes",
        "Require the external Terraform backend password before remote mutation",
        "Validate the public backup encryption recipient before remote mutation",
        "TERRAFORM_STATE_POSTGRESQL_PASSWORD",
        "TERRAFORM_STATE_BACKUP_AGE_RECIPIENT",
        "terraform_state_postgresql_password | default('') | length >= terraform_state_secret_min_length",
        "terraform_state_backup_age_recipient is match('^age1[0-9a-z]{20,}$')",
    ),
    "Ansible terraform-state playbook",
)
if "management.yml" in playbook or "data_management" in playbook:
    fail("Terraform state playbook is coupled to management inventory")
require(
    terraform_state_vars,
    (
        "lookup('env', 'TERRAFORM_STATE_POSTGRESQL_PASSWORD')",
        "lookup('env', 'TERRAFORM_STATE_BACKUP_AGE_RECIPIENT')",
    ),
    "terraform-state group variables",
)
if "TERRAFORM_STATE_BACKUP_AGE_IDENTITY" in terraform_state_vars + playbook:
    fail("the private age identity is passed into remote Ansible")
if playbook.index("Require the external Terraform backend password") > playbook.index(
    "Read Hetzner instance ID"
):
    fail("the PostgreSQL password check is not before remote mutation")
if playbook.index("Validate the public backup encryption recipient") > playbook.index(
    "Read Hetzner instance ID"
):
    fail("the age recipient check is not before remote mutation")
password_assertion = re.search(
    r"Require the external Terraform backend password.*?no_log: true",
    playbook,
    re.DOTALL,
)
if password_assertion is None:
    fail("the pre-mutation PostgreSQL password assertion is not protected by no_log")

for ansible_path in (ROOT / "infrastructure/ansible").rglob("*"):
    if not ansible_path.is_file() or ansible_path.suffix not in {".yml", ".yaml", ".j2"}:
        continue
    ansible_source = ansible_path.read_text(encoding="utf-8")
    if "TERRAFORM_STATE_BACKUP_AGE_IDENTITY" in ansible_source:
        fail(
            "private age identity referenced by Ansible: "
            f"{ansible_path.relative_to(ROOT)}"
        )

postgres_tasks = read(
    "infrastructure/ansible/roles/terraform_state_postgresql/tasks/main.yml"
)
postgres_config = read(
    "infrastructure/ansible/roles/terraform_state_postgresql/templates/postgresql.conf.j2"
)
postgres_hba = read(
    "infrastructure/ansible/roles/terraform_state_postgresql/templates/pg_hba.conf.j2"
)
backend_objects = read(
    "infrastructure/ansible/roles/terraform_state_postgresql/templates/backend-objects.sql.j2"
)
role_sql = read(
    "infrastructure/ansible/roles/terraform_state_postgresql/templates/roles.sql.j2"
)
firewall = read(
    "infrastructure/ansible/roles/terraform_state_firewall/templates/nftables.conf.j2"
)
backup_template = read(
    "infrastructure/ansible/roles/terraform_state_postgresql/templates/terraform-state-backup.sh.j2"
)
require(
    postgres_config,
    (
        "listen_addresses = '{{ postgresql_bind_address }}'",
        "password_encryption = 'scram-sha-256'",
        "ssl = on",
        "ssl_min_protocol_version = 'TLSv1.2'",
        "log_destination = 'jsonlog'",
        "log_lock_waits = on",
    ),
    "PostgreSQL configuration",
)
require(
    postgres_hba,
    (
        "hostssl",
        "127.0.0.1/32",
        "scram-sha-256",
        "hostnossl",
        "0.0.0.0/0",
        "reject",
        "::/0",
    ),
    "PostgreSQL HBA",
)
if "data-mgmt" in postgres_tasks + postgres_config + postgres_hba + backend_objects:
    fail("dedicated PostgreSQL role references data-mgmt")
for application_db in ("gitea", "harbor", "backstage"):
    if re.search(rf"\b{application_db}\b", backend_objects + role_sql, re.IGNORECASE):
        fail(f"Terraform backend SQL contains application database token {application_db}")
require(
    backend_objects,
    (
        "public.global_states_id_seq",
        "CREATE SCHEMA IF NOT EXISTS {{ terraform_state_management_schema }}",
        "CREATE SCHEMA IF NOT EXISTS {{ terraform_state_lock_probe_schema }}",
        "id bigint NOT NULL DEFAULT nextval('public.global_states_id_seq') PRIMARY KEY",
        "name text UNIQUE",
        "data text",
        "CREATE UNIQUE INDEX IF NOT EXISTS states_by_name",
        "GRANT SELECT, INSERT, UPDATE, DELETE",
        "REVOKE ALL ON TABLE",
    ),
    "Terraform backend SQL",
)
if re.search(r"GRANT\s+CREATE\s+ON\s+SCHEMA", backend_objects, re.IGNORECASE):
    fail("Terraform backend role must not receive schema DDL privileges")
require(
    role_sql,
    (
        "NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS",
        "terraform_state_postgresql_password | b64encode",
    ),
    "Terraform backend role SQL",
)
require(
    firewall,
    (
        "policy drop",
        "ip saddr @operator_ssh_v4 tcp dport 22",
        'iifname "lo" accept',
    ),
    "Terraform state host firewall",
)
if "5432" in firewall:
    fail("host firewall must not add a public PostgreSQL rule")
require(
    backup_template,
    (
        "pg_dump",
        "--format=custom",
        "age --recipient",
        "plaintextSha256",
        "encryptedSha256",
        "ecommerce/backups/postgresql/",
    ),
    "PostgreSQL backup interface",
)

bootstrap_state_helper = read("scripts/bootstrap-local-state.sh")
bootstrap_state_wrapper = read("scripts/terraform-state-bootstrap-state.sh")
require(
    bootstrap_state_helper,
    (
        "authoritative bootstrap state must remain outside the repository and OneDrive",
        "bootstrap plan requires -out=<absolute-path>",
        "bootstrap plan must remain outside the authoritative state directory",
        "sha256sum",
        ".lineage",
        ".serial",
        "age --recipient",
        "restore-test",
        "validate-bootstrap-state-path.py",
        "output-inventory",
        '-state="$state_file"',
        "caller-supplied Terraform state or backup path options are forbidden",
        "TF_CLI_ARGS_plan",
        "TF_WORKSPACE=default",
        "unset BOOTSTRAP_STATE_DIR",
    ),
    "shared bootstrap state helper",
)
bootstrap_path_validator = read("scripts/validate-bootstrap-state-path.py")
require(
    bootstrap_path_validator,
    (
        "pwd.getpwuid(os.geteuid()).pw_dir",
        "os.O_NOFOLLOW",
        "dir_fd=parent_fd",
        "must not be writable by group or other",
        "owner must be root or the invoking user",
        "permissions must equal 0600",
    ),
    "bootstrap state path validator",
)
require(
    bootstrap_state_wrapper,
    (
        "BOOTSTRAP_ROOT=infrastructure/hetzner/bootstrap/terraform-state",
        "BOOTSTRAP_STATE_SLUG=bootstrap-terraform-state",
    ),
    "Terraform state bootstrap wrapper",
)

locking_harness = read("scripts/test-terraform-pg-locking.sh")
require(
    locking_harness,
    (
        "terraform_pg_require_runtime",
        "tlsWrongCaRejected: true",
        "tlsWrongHostnameRejected: true",
        "FROM pg_locks",
        "advisoryLockObservedDirectly: true",
        "run_contender \"$contender_one_log\"",
        "run_contender \"$contender_two_log\"",
        "Workspace is already locked: default",
        "distinctClientProcesses: true",
        "postReleaseSucceeded: true",
        'status: "PROVEN"',
    ),
    "PostgreSQL locking harness",
)
for forbidden in ("-lock=false", "force-unlock"):
    if forbidden in locking_harness:
        fail(f"PostgreSQL locking harness contains forbidden token {forbidden}")

initializer = read("scripts/init-terraform-pg-backend.sh")
require(
    initializer,
    (
        "TERRAFORM_PG_LOCKING_EVIDENCE",
        "MANAGEMENT_STATE_INSPECTION_EVIDENCE",
        "MANAGEMENT_STATE_ACTIVATION_DECISION",
        'status == "HUMAN_APPROVED"',
        'decision == "initialize-empty"',
        "allSourcesAbsent == true",
        'legacyVersionHistory.verdict == "ZERO_HISTORY"',
        "observe_management_target preflight",
        "evaluate-terraform-pg-target.py",
        "target_preflight_verdict",
        "observe_management_target post-init",
        "terraform -chdir=infrastructure/hetzner/management init -reconfigure -input=false",
    ),
    "management pg initializer",
)
for forbidden in ("-migrate-state", "terraform state push", "terraform state mv"):
    if forbidden in initializer:
        fail(f"management pg initializer contains forbidden migration token {forbidden}")

inspector = read("scripts/inspect-management-state.sh")
require(
    inspector,
    (
        "ecommerce-management-tfstate-20260820-70b94831",
        "ecommerce/management/terraform.tfstate",
        "inspect-s3-version-history.py",
        "ListObjectVersions",
        "legacyVersionHistoryCheckedAuthenticated",
        "HISTORICAL_STATE_PRESENT",
        "UNKNOWN",
        "lineage",
        "serial",
        "resourceCount",
        'decision: "HUMAN_REQUIRED"',
    ),
    "management state source inspector",
)

if "infrastructure/ansible/inventory/terraform-state.generated.yml" not in ignore:
    fail(".gitignore does not protect the generated terraform-state inventory")

runbook = read("docs/runbooks/management-foundation.md")
require(
    runbook,
    (
        "$HOME/.config/ecommerce-1/.env",
        ".env.example",
        "./scripts/init-project-secrets.sh",
        "python3 scripts/run-with-project-env.py --check-only",
        "python3 scripts/run-with-project-env.py --",
        "identity/recipient",
        "GENERATE CENTRAL PROJECT SECRETS",
    ),
    "management foundation runbook",
)
if "group_vars/terraform_state_bootstrap/secrets.yml" in runbook:
    fail("runbook still documents the retired terraform-state Vault file")

# Exercise the renderer with a non-secret synthetic Terraform output contract.
renderer_input = {
    "server_id": 123456,
    "server_name": "terraform-state-mgmt",
    "server_ipv4": "1.1.1.1",
    "hostname": "terraform-state-mgmt",
    "ansible_host": "1.1.1.1",
    "service": "terraform-state-postgresql",
    "postgresql_bind_address": "127.0.0.1",
    "postgresql_volume_device": "/dev/disk/by-id/scsi-0HC_Volume_12345678",
    "postgresql_volume_id": 12345678,
    "ssh_allowed_ipv4_cidrs": ["198.51.100.10/32"],
    "public_postgresql_exposed": False,
    "management_plane_dependency": False,
}
with tempfile.TemporaryDirectory(prefix="terraform-state-known-hosts-") as directory:
    known_hosts = Path(directory) / "known_hosts"
    known_hosts.write_text(
        "1.1.1.1 ssh-ed25519 AAAAofflinefixture\n", encoding="utf-8"
    )
    known_hosts.chmod(0o600)
    render = subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts/render-terraform-state-inventory.py"),
            "--known-hosts",
            str(known_hosts),
        ],
        input=json.dumps(renderer_input),
        text=True,
        capture_output=True,
        check=False,
    )
    if render.returncode != 0:
        fail(f"inventory renderer self-test failed: {render.stderr.strip()}")
    for rendered_token in (
        "terraform_state_bootstrap:",
        "ansible_host: 1.1.1.1",
        "terraform_state_server_id: 123456",
        "StrictHostKeyChecking=yes",
        "postgresql_volume_id: 12345678",
        "public_postgresql_exposed: false",
    ):
        if rendered_token not in render.stdout:
            fail(f"inventory renderer output is missing {rendered_token!r}")

# Reproduce the decimal-string IDs returned by the real Hetzner Terraform state.
hetzner_renderer_input = {
    **renderer_input,
    "server_id": "162968571",
    "postgresql_volume_id": "106666210",
    "postgresql_volume_device": "/dev/disk/by-id/scsi-0HC_Volume_106666210",
}
normalized_render = subprocess.run(
    [
        sys.executable,
        str(ROOT / "scripts/render-terraform-state-inventory.py"),
        "--output-format",
        "json",
    ],
    input=json.dumps(hetzner_renderer_input),
    text=True,
    capture_output=True,
    check=False,
)
if normalized_render.returncode != 0:
    fail(f"inventory renderer string-ID test failed: {normalized_render.stderr.strip()}")
normalized_contract = json.loads(normalized_render.stdout)
if (
    type(normalized_contract.get("server_id")) is not int
    or normalized_contract["server_id"] != 162968571
):
    fail("inventory renderer did not normalize server_id to an integer")
if (
    type(normalized_contract.get("postgresql_volume_id")) is not int
    or normalized_contract["postgresql_volume_id"] != 106666210
):
    fail("inventory renderer did not normalize postgresql_volume_id to an integer")
if normalized_contract.get("postgresql_volume_device") != (
    "/dev/disk/by-id/scsi-0HC_Volume_106666210"
):
    fail("inventory renderer changed the Hetzner volume device")

invalid_ids = (
    True,
    False,
    0,
    -1,
    1.5,
    "",
    "0",
    "01",
    "-1",
    "+1",
    " 123",
    "123 ",
    "1.0",
    "1e3",
    "abc",
    None,
)
for field in ("server_id", "postgresql_volume_id"):
    for invalid_id in invalid_ids:
        invalid_input = {**renderer_input, field: invalid_id}
        rejected_render = subprocess.run(
            [
                sys.executable,
                str(ROOT / "scripts/render-terraform-state-inventory.py"),
                "--output-format",
                "json",
            ],
            input=json.dumps(invalid_input),
            text=True,
            capture_output=True,
            check=False,
        )
        if rejected_render.returncode == 0:
            fail(f"inventory renderer accepted invalid {field}: {invalid_id!r}")
        expected_error = f"{field} must be a positive integer"
        if expected_error not in rejected_render.stderr:
            fail(
                f"inventory renderer returned an unexpected error for invalid {field}: "
                f"{rejected_render.stderr.strip()}"
            )

# No AWS provider/cloud integration is active in any Terraform source.
for path in ROOT.rglob("*.tf"):
    if ".terraform" in path.parts:
        continue
    source = path.read_text(encoding="utf-8")
    if re.search(r'provider\s+"aws"\s*\{', source):
        fail(f"AWS provider is active in {path.relative_to(ROOT)}")
    if re.search(r"(?m)^\s*cloud\s*\{", source):
        fail(f"HCP Terraform cloud block is active in {path.relative_to(ROOT)}")

print("Terraform PostgreSQL backend foundation static contract: valid")
