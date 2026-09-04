#!/usr/bin/env python3
"""Offline adversarial tests for the six Terraform PostgreSQL blockers."""

from __future__ import annotations

import json
import os
import pwd
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
KEY = "ecommerce/management/terraform.tfstate"
SYSTEM_HOME = Path(pwd.getpwuid(os.geteuid()).pw_dir)


def run(command: list[str], *, env: dict[str, str] | None = None, input_text: str | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        cwd=ROOT,
        env=env,
        input=input_text,
        text=True,
        capture_output=True,
        check=False,
    )


def inventory_contract() -> dict[str, object]:
    return {
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


class PgConnectionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.environment = {key: value for key, value in os.environ.items() if not key.startswith("PG")}
        self.environment.update(
            {
                "PG_CONN_STR": "postgres://terraform_backend@127.0.0.1:15432/terraform_backend?sslmode=verify-full",
                "TERRAFORM_PG_TUNNEL_HOST": "127.0.0.1",
                "TERRAFORM_PG_TUNNEL_PORT": "15432",
            }
        )

    def validate(self, connection: str) -> subprocess.CompletedProcess[str]:
        environment = dict(self.environment)
        environment["PG_CONN_STR"] = connection
        return run(["python3", "scripts/validate-terraform-pg-connection.py"], env=environment)

    def test_canonical_connection_passes(self) -> None:
        self.assertEqual(self.validate(self.environment["PG_CONN_STR"]).returncode, 0)

    def test_adversarial_connections_fail(self) -> None:
        invalid = (
            "postgres://terraform_backend@localhost:15432/terraform_backend?sslmode=verify-full",
            "postgres://terraform_backend@127.0.0.1:15432/terraform_backend?sslmode=require",
            "postgres://terraform_backend@127.0.0.1:15432/terraform_backend?sslmode=disable",
            "postgres://terraform_backend@127.0.0.1:15432/terraform_backend?sslmode=verify-full&sslmode=disable",
            "postgres://terraform_backend@127.0.0.1:15432/terraform_backend?sslmode=verify-full&host=evil",
            "postgres://terraform_backend@127.0.0.1:15433/terraform_backend?sslmode=verify-full",
            "postgres://other@127.0.0.1:15432/terraform_backend?sslmode=verify-full",
            "postgres://terraform_backend@127.0.0.1:15432/other?sslmode=verify-full",
            "postgres://terraform_backend@127.0.0.1:15432/terraform_backend?sslmode=verify-full&sslrootcert=/tmp/evil",
            "postgres://terraform_backend:secret@127.0.0.1:15432/terraform_backend?sslmode=verify-full",
            "postgres://terraform_backend@127.0.0.1:15432/terraform_backend?sslmode=verify-full&unknown=value",
            "postgres://terraform_backend@127.0.0.1:15432/terraform_backend?sslmode=verify-full#fragment",
        )
        for connection in invalid:
            with self.subTest(connection=connection):
                self.assertNotEqual(self.validate(connection).returncode, 0)

    def test_runtime_rejects_bad_ca_paths_and_competing_environment(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pg-runtime-") as directory:
            temporary = Path(directory)
            ca = temporary / "ca.crt"
            ca.write_text("offline fixture\n", encoding="utf-8")
            ca.chmod(0o600)
            shell = ". scripts/lib.sh; . scripts/lib-terraform-pg.sh; repository=$(pwd -P); terraform_pg_require_runtime"
            environment = dict(self.environment)
            environment.update({"PGPASSWORD": "offline-only", "PGSSLROOTCERT": str(ca)})
            self.assertEqual(run(["sh", "-c", shell], env=environment).returncode, 0)
            environment["PGSSLROOTCERT"] = str(temporary / "missing-ca.crt")
            self.assertNotEqual(run(["sh", "-c", shell], env=environment).returncode, 0)
            ca_link = temporary / "ca-link.crt"
            ca_link.symlink_to(ca)
            environment["PGSSLROOTCERT"] = str(ca_link)
            self.assertNotEqual(run(["sh", "-c", shell], env=environment).returncode, 0)
            environment["PGSSLROOTCERT"] = str(ROOT / "README.md")
            self.assertNotEqual(run(["sh", "-c", shell], env=environment).returncode, 0)
            environment["PGSSLROOTCERT"] = str(ca)
            environment["PGHOST"] = "evil.invalid"
            self.assertNotEqual(run(["sh", "-c", shell], env=environment).returncode, 0)

    def test_tls_fixture_rejects_wrong_ca_and_wrong_hostname(self) -> None:
        with tempfile.TemporaryDirectory(prefix="tls-policy-") as directory:
            temporary = Path(directory)
            commands = (
                [
                    "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                    "-days", "1", "-subj", "/CN=offline-approved-ca",
                    "-keyout", str(temporary / "approved-ca.key"),
                    "-out", str(temporary / "approved-ca.crt"),
                ],
                [
                    "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                    "-days", "1", "-subj", "/CN=offline-wrong-ca",
                    "-keyout", str(temporary / "wrong-ca.key"),
                    "-out", str(temporary / "wrong-ca.crt"),
                ],
                [
                    "openssl", "req", "-newkey", "rsa:2048", "-nodes",
                    "-subj", "/CN=localhost",
                    "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1",
                    "-keyout", str(temporary / "server.key"),
                    "-out", str(temporary / "server.csr"),
                ],
                [
                    "openssl", "x509", "-req", "-days", "1",
                    "-in", str(temporary / "server.csr"),
                    "-CA", str(temporary / "approved-ca.crt"),
                    "-CAkey", str(temporary / "approved-ca.key"),
                    "-CAcreateserial", "-copy_extensions", "copy",
                    "-out", str(temporary / "server.crt"),
                ],
            )
            for command in commands:
                result = run(command)
                self.assertEqual(result.returncode, 0, result.stderr)
            server = str(temporary / "server.crt")
            approved = run(
                [
                    "openssl", "verify", "-CAfile", str(temporary / "approved-ca.crt"),
                    "-verify_ip", "127.0.0.1", server,
                ]
            )
            self.assertEqual(approved.returncode, 0, approved.stderr)
            wrong_ca = run(
                [
                    "openssl", "verify", "-CAfile", str(temporary / "wrong-ca.crt"),
                    "-verify_ip", "127.0.0.1", server,
                ]
            )
            self.assertNotEqual(wrong_ca.returncode, 0)
            wrong_hostname = run(
                [
                    "openssl", "verify", "-CAfile", str(temporary / "approved-ca.crt"),
                    "-verify_hostname", "terraform-state.invalid", server,
                ]
            )
            self.assertNotEqual(wrong_hostname.returncode, 0)


class BootstrapStateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory(
            prefix="bootstrap-state-",
            dir=SYSTEM_HOME,
        )

    def tearDown(self) -> None:
        self.directory.cleanup()

    def paths(self) -> tuple[Path, Path, Path]:
        temporary = Path(self.directory.name)
        xdg = temporary / "xdg"
        state_dir = xdg / "ecommerce-1/terraform/bootstrap-terraform-state"
        return temporary, xdg, state_dir

    def prepare_state_tree(self, *, providers: bool = False) -> tuple[Path, Path, Path]:
        temporary, xdg, state_dir = self.paths()
        state_dir.mkdir(parents=True)
        state_dir.chmod(0o700)
        terraform_data = state_dir / "terraform-data"
        terraform_data.mkdir()
        terraform_data.chmod(0o700)
        if providers:
            provider_directory = terraform_data / "providers"
            provider_directory.mkdir()
            provider_directory.chmod(0o700)
        return temporary, xdg, state_dir

    def fake_environment(self, xdg: Path) -> tuple[dict[str, str], Path]:
        temporary = Path(self.directory.name)
        fake_bin = temporary / "bin"
        fake_bin.mkdir(exist_ok=True)
        terraform = fake_bin / "terraform"
        terraform.write_text(
            """#!/bin/sh
set -eu
{
  printf 'TF_DATA_DIR=%s\\n' "${TF_DATA_DIR-unset}"
  printf 'TF_WORKSPACE=%s\\n' "${TF_WORKSPACE-unset}"
  printf 'TF_CLI_ARGS=%s\\n' "${TF_CLI_ARGS-unset}"
  printf 'TF_CLI_ARGS_plan=%s\\n' "${TF_CLI_ARGS_plan-unset}"
  printf 'argument=%s\\n' "$@"
} >"${TERRAFORM_TEST_MARKER:?}"
""",
            encoding="utf-8",
        )
        terraform.chmod(0o700)
        marker = temporary / "terraform-invoked"
        environment = os.environ.copy()
        environment.update(
            {
                "XDG_STATE_HOME": str(xdg),
                "PATH": f"{fake_bin}:{environment['PATH']}",
                "TERRAFORM_TEST_MARKER": str(marker),
            }
        )
        return environment, marker

    def invoke_init(self, scenario: str) -> tuple[subprocess.CompletedProcess[str], Path]:
        temporary, xdg, state_dir = self.prepare_state_tree()
        state = state_dir / "terraform.tfstate"
        backup = state_dir / "terraform.tfstate.backup"
        if scenario == "normal":
            state.write_text("{}", encoding="utf-8")
            state.chmod(0o600)
        elif scenario == "state-symlink":
            target = temporary / "target-state"
            target.write_text("{}", encoding="utf-8")
            target.chmod(0o600)
            state.symlink_to(target)
        elif scenario == "backup-symlink":
            state.write_text("{}", encoding="utf-8")
            state.chmod(0o600)
            target = temporary / "target-backup"
            target.write_text("{}", encoding="utf-8")
            target.chmod(0o600)
            backup.symlink_to(target)
        elif scenario == "backup-bad-mode":
            backup.write_text("{}", encoding="utf-8")
            backup.chmod(0o644)
        elif scenario == "bad-mode":
            state.write_text("{}", encoding="utf-8")
            state.chmod(0o644)
        elif scenario == "wrong-type":
            state.mkdir()
        elif scenario == "terraform-data-symlink":
            terraform_data = state_dir / "terraform-data"
            terraform_data.rmdir()
            target = temporary / "target-terraform-data"
            target.mkdir()
            terraform_data.symlink_to(target, target_is_directory=True)
        environment, marker = self.fake_environment(xdg)
        result = run(["./scripts/terraform-state-bootstrap-state.sh", "init"], env=environment)
        return result, marker

    def test_normal_state_passes(self) -> None:
        result, marker = self.invoke_init("normal")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(marker.exists())

    def test_unsafe_state_paths_fail(self) -> None:
        for scenario in (
            "state-symlink",
            "backup-symlink",
            "backup-bad-mode",
            "bad-mode",
            "wrong-type",
            "terraform-data-symlink",
        ):
            with self.subTest(scenario=scenario):
                self.directory.cleanup()
                self.directory = tempfile.TemporaryDirectory(
                    prefix="bootstrap-state-",
                    dir=SYSTEM_HOME,
                )
                result, marker = self.invoke_init(scenario)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(marker.exists())

    def test_bootstrap_state_directory_environment_cannot_override_wrapper(self) -> None:
        temporary, xdg, state_dir = self.prepare_state_tree()
        hostile_directory = temporary / "caller-state-directory"
        environment, marker = self.fake_environment(xdg)
        environment["BOOTSTRAP_STATE_DIR"] = str(hostile_directory)
        result = run(
            ["./scripts/terraform-state-bootstrap-state.sh", "init"],
            env=environment,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        invocation = marker.read_text(encoding="utf-8")
        self.assertIn(f"TF_DATA_DIR={state_dir / 'terraform-data'}", invocation)
        self.assertFalse(hostile_directory.exists())

    def test_untrusted_xdg_and_unsafe_ancestors_fail(self) -> None:
        scenarios = ("tmp", "group-writable", "other-writable", "parent-symlink")
        for scenario in scenarios:
            with self.subTest(scenario=scenario):
                self.directory.cleanup()
                self.directory = tempfile.TemporaryDirectory(
                    prefix="bootstrap-state-",
                    dir=SYSTEM_HOME,
                )
                temporary, xdg, state_dir = self.paths()
                if scenario == "tmp":
                    xdg = Path(tempfile.gettempdir()) / f"bootstrap-shared-{os.getpid()}"
                elif scenario == "parent-symlink":
                    real_xdg = temporary / "real-xdg"
                    real_xdg.mkdir()
                    xdg.symlink_to(real_xdg, target_is_directory=True)
                else:
                    xdg.mkdir()
                    xdg.chmod(0o770 if scenario == "group-writable" else 0o707)
                environment, marker = self.fake_environment(xdg)
                result = run(
                    ["./scripts/terraform-state-bootstrap-state.sh", "init"],
                    env=environment,
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(marker.exists())
                self.assertFalse(state_dir.joinpath("terraform.tfstate").exists())

    def test_bad_state_directory_mode_fails(self) -> None:
        _, xdg, state_dir = self.prepare_state_tree()
        state_dir.chmod(0o755)
        environment, marker = self.fake_environment(xdg)
        result = run(
            ["./scripts/terraform-state-bootstrap-state.sh", "init"],
            env=environment,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(marker.exists())

    def test_repository_and_onedrive_roots_fail_without_creation(self) -> None:
        candidates = (ROOT, Path("/mnt/c/Users/admin/OneDrive"))
        for candidate in candidates:
            with self.subTest(candidate=candidate):
                environment, marker = self.fake_environment(candidate)
                result = run(
                    ["./scripts/terraform-state-bootstrap-state.sh", "init"],
                    env=environment,
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(marker.exists())

    @unittest.skipUnless(os.geteuid() == 0, "owner mismatch requires root")
    def test_wrong_owner_fails_when_privileges_allow_fixture(self) -> None:
        _, xdg, _ = self.prepare_state_tree()
        os.chown(xdg, 65534, 65534)
        environment, marker = self.fake_environment(xdg)
        result = run(
            ["./scripts/terraform-state-bootstrap-state.sh", "init"],
            env=environment,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(marker.exists())

    def test_all_state_control_argument_forms_fail_before_terraform(self) -> None:
        temporary, xdg, state_dir = self.prepare_state_tree(providers=True)
        state = state_dir / "terraform.tfstate"
        backup = state_dir / "terraform.tfstate.backup"
        state.write_text("authoritative sentinel\n", encoding="utf-8")
        state.chmod(0o600)
        backup.write_text("backup sentinel\n", encoding="utf-8")
        backup.chmod(0o600)
        hostile = temporary / "hostile-state"
        plan = temporary / "reviewed.tfplan"
        argument_sets = (
            ("-state", str(hostile)),
            (f"-state={hostile}",),
            ("--state", str(hostile)),
            (f"--state={hostile}",),
            ("-state-out", str(hostile)),
            (f"-state-out={hostile}",),
            ("--state-out", str(hostile)),
            (f"--state-out={hostile}",),
            ("-backup", str(hostile)),
            (f"-backup={hostile}",),
            ("--backup", str(hostile)),
            (f"--backup={hostile}",),
        )
        for hostile_arguments in argument_sets:
            with self.subTest(arguments=hostile_arguments):
                environment, marker = self.fake_environment(xdg)
                marker.unlink(missing_ok=True)
                result = run(
                    [
                        "./scripts/terraform-state-bootstrap-state.sh",
                        "terraform",
                        "plan",
                        "-input=false",
                        f"-out={plan}",
                        *hostile_arguments,
                    ],
                    env=environment,
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("state or backup path options are forbidden", result.stderr)
                self.assertNotIn(str(hostile), result.stderr)
                self.assertFalse(marker.exists())
                self.assertFalse(hostile.exists())
                self.assertEqual(state.read_text(encoding="utf-8"), "authoritative sentinel\n")
                self.assertEqual(backup.read_text(encoding="utf-8"), "backup sentinel\n")

    def test_normal_plan_keeps_wrapper_authority_over_state_environment(self) -> None:
        temporary, xdg, state_dir = self.prepare_state_tree(providers=True)
        environment, marker = self.fake_environment(xdg)
        environment.update(
            {
                "HOME": "/tmp/caller-home",
                "TF_DATA_DIR": "/tmp/caller-terraform-data",
                "TF_WORKSPACE": "caller-workspace",
                "TF_CLI_ARGS": "-backup=/tmp/caller-backup",
                "TF_CLI_ARGS_plan": "-state=/tmp/caller-state",
                "BOOTSTRAP_STATE_DIR": "/tmp/caller-state-directory",
            }
        )
        plan = temporary / "reviewed.tfplan"
        result = run(
            [
                "./scripts/terraform-state-bootstrap-state.sh",
                "terraform",
                "plan",
                "-input=false",
                f"-out={plan}",
            ],
            env=environment,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        invocation = marker.read_text(encoding="utf-8")
        self.assertIn(f"TF_DATA_DIR={state_dir / 'terraform-data'}", invocation)
        self.assertIn("TF_WORKSPACE=default", invocation)
        self.assertIn("TF_CLI_ARGS=unset", invocation)
        self.assertIn("TF_CLI_ARGS_plan=unset", invocation)
        self.assertIn(f"argument=-state={state_dir / 'terraform.tfstate'}", invocation)
        self.assertIn(f"argument=-out={plan}", invocation)

    def test_plan_output_cannot_alias_state_or_backup(self) -> None:
        temporary, xdg, state_dir = self.prepare_state_tree(providers=True)
        state = state_dir / "terraform.tfstate"
        backup = state_dir / "terraform.tfstate.backup"
        state.write_text("authoritative sentinel\n", encoding="utf-8")
        state.chmod(0o600)
        backup.write_text("backup sentinel\n", encoding="utf-8")
        backup.chmod(0o600)
        state_alias = temporary / "state-alias"
        state_alias.symlink_to(state)
        for plan_output in (state, backup, state_alias):
            with self.subTest(plan_output=plan_output):
                environment, marker = self.fake_environment(xdg)
                marker.unlink(missing_ok=True)
                result = run(
                    [
                        "./scripts/terraform-state-bootstrap-state.sh",
                        "terraform",
                        "plan",
                        "-input=false",
                        f"-out={plan_output}",
                    ],
                    env=environment,
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(marker.exists())
                self.assertEqual(state.read_text(encoding="utf-8"), "authoritative sentinel\n")
                self.assertEqual(backup.read_text(encoding="utf-8"), "backup sentinel\n")


class BootstrapStateTerraformIntegrationTests(unittest.TestCase):
    def test_terraform_1_15_5_reads_only_the_authoritative_synthetic_state(self) -> None:
        version = run(["terraform", "version", "-json"])
        self.assertEqual(version.returncode, 0, version.stderr)
        self.assertEqual(json.loads(version.stdout)["terraform_version"], "1.15.5")

        with tempfile.TemporaryDirectory(
            prefix="bootstrap-terraform-cli-",
            dir=SYSTEM_HOME,
        ) as directory, tempfile.TemporaryDirectory(
            prefix="offline-wrapper-test-",
            dir=ROOT / "infrastructure/hetzner/bootstrap",
        ) as module_directory:
            temporary = Path(directory)
            module = Path(module_directory)
            (module / "main.tf").write_text(
                """terraform {
  required_version = "= 1.15.5"
}

output "marker" {
  value = "authoritative"
}
""",
                encoding="utf-8",
            )
            module_relative = module.relative_to(ROOT)
            xdg = temporary / "xdg"
            environment = os.environ.copy()
            environment.update(
                {
                    "BOOTSTRAP_ROOT": str(module_relative),
                    "BOOTSTRAP_STATE_SLUG": "offline-bootstrap-state",
                    "BOOTSTRAP_BACKUP_PREFIX": "offline-bootstrap",
                    "XDG_STATE_HOME": str(xdg),
                }
            )
            init = run(["./scripts/bootstrap-local-state.sh", "init"], env=environment)
            self.assertEqual(init.returncode, 0, init.stderr)

            state = xdg / "ecommerce-1/terraform/offline-bootstrap-state/terraform.tfstate"
            provider_directory = state.parent / "terraform-data/providers"
            provider_directory.mkdir()
            provider_directory.chmod(0o700)
            state.write_text(
                json.dumps(
                    {
                        "version": 4,
                        "terraform_version": "1.15.5",
                        "serial": 1,
                        "lineage": "11111111-1111-1111-1111-111111111111",
                        "outputs": {
                            "marker": {
                                "value": "authoritative",
                                "type": "string",
                                "sensitive": False,
                            }
                        },
                        "resources": [],
                        "check_results": None,
                    }
                ),
                encoding="utf-8",
            )
            state.chmod(0o600)
            plan = temporary / "reviewed.tfplan"
            normal = run(
                [
                    "./scripts/bootstrap-local-state.sh",
                    "terraform",
                    "plan",
                    "-input=false",
                    f"-out={plan}",
                ],
                env=environment,
            )
            self.assertEqual(normal.returncode, 0, normal.stderr)
            shown = run(["terraform", "show", "-json", str(plan)])
            self.assertEqual(shown.returncode, 0, shown.stderr)
            prior_outputs = json.loads(shown.stdout)["prior_state"]["values"]["outputs"]
            self.assertEqual(prior_outputs["marker"]["value"], "authoritative")

            hostile = temporary / "hostile.tfstate"
            rejected = run(
                [
                    "./scripts/bootstrap-local-state.sh",
                    "terraform",
                    "plan",
                    "-input=false",
                    f"-out={temporary / 'hostile.tfplan'}",
                    f"-state={hostile}",
                ],
                env=environment,
            )
            self.assertNotEqual(rejected.returncode, 0)
            self.assertFalse(hostile.exists())


class InventoryTests(unittest.TestCase):
    def terraform_state(self, contract: dict[str, object] | None) -> dict[str, object]:
        outputs: dict[str, object] = {}
        if contract is not None:
            type_map = {
                key: (["list", "string"] if key == "ssh_allowed_ipv4_cidrs" else "bool" if isinstance(value, bool) else "number" if isinstance(value, int) else "string")
                for key, value in contract.items()
            }
            outputs["inventory_contract"] = {
                "value": contract,
                "type": ["object", type_map],
                "sensitive": False,
            }
        return {
            "version": 4,
            "terraform_version": "1.15.5",
            "serial": 1,
            "lineage": "11111111-1111-1111-1111-111111111111",
            "outputs": outputs,
            "resources": [],
            "check_results": None,
        }

    def invoke_output(self, contract: dict[str, object] | None) -> subprocess.CompletedProcess[str]:
        temporary = Path(self.directory.name)
        xdg = temporary / "xdg"
        state_dir = xdg / "ecommerce-1/terraform/bootstrap-terraform-state"
        state_dir.mkdir(parents=True)
        state_dir.chmod(0o700)
        state = state_dir / "terraform.tfstate"
        state.write_text(json.dumps(self.terraform_state(contract)), encoding="utf-8")
        state.chmod(0o600)
        environment = os.environ.copy()
        environment["XDG_STATE_HOME"] = str(xdg)
        return run(["./scripts/terraform-state-bootstrap-state.sh", "output-inventory"], env=environment)

    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory(
            prefix="inventory-output-",
            dir=SYSTEM_HOME,
        )

    def tearDown(self) -> None:
        self.directory.cleanup()

    def test_external_state_inventory_output_passes(self) -> None:
        result = self.invoke_output(inventory_contract())
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)["server_id"], 123456)

    def test_missing_or_invalid_inventory_output_fails(self) -> None:
        temporary = Path(self.directory.name)
        environment = os.environ.copy()
        environment["XDG_STATE_HOME"] = str(temporary / "missing-xdg")
        missing = run(
            ["./scripts/terraform-state-bootstrap-state.sh", "output-inventory"],
            env=environment,
        )
        self.assertNotEqual(missing.returncode, 0)
        self.directory.cleanup()
        self.directory = tempfile.TemporaryDirectory(
            prefix="inventory-output-",
            dir=SYSTEM_HOME,
        )
        self.assertNotEqual(self.invoke_output(None).returncode, 0)
        self.directory.cleanup()
        self.directory = tempfile.TemporaryDirectory(
            prefix="inventory-output-",
            dir=SYSTEM_HOME,
        )
        invalid = inventory_contract()
        invalid["postgresql_volume_device"] = "/dev/disk/by-id/scsi-0HC_Volume_999"
        self.assertNotEqual(self.invoke_output(invalid).returncode, 0)

    def test_inventory_requires_matching_pinned_known_hosts(self) -> None:
        with tempfile.TemporaryDirectory(prefix="known-hosts-") as directory:
            known_hosts = Path(directory) / "known_hosts"
            known_hosts.write_text("1.1.1.1 ssh-ed25519 AAAAofflinefixture\n", encoding="utf-8")
            known_hosts.chmod(0o600)
            command = [
                "python3",
                "scripts/render-terraform-state-inventory.py",
                "--known-hosts",
                str(known_hosts),
            ]
            result = run(command, input_text=json.dumps(inventory_contract()))
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("StrictHostKeyChecking=yes", result.stdout)
            bad = inventory_contract()
            bad["server_id"] = 0
            self.assertNotEqual(run(command, input_text=json.dumps(bad)).returncode, 0)


class MetadataEvaluatorTests(unittest.TestCase):
    def test_s3_xml_parser_keeps_only_safe_exact_key_metadata(self) -> None:
        xml = """<?xml version="1.0" encoding="UTF-8"?>
<ListVersionsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <EncodingType>url</EncodingType><IsTruncated>false</IsTruncated>
  <Version><Key>ecommerce%2Fmanagement%2Fterraform.tfstate</Key><VersionId>v1</VersionId><IsLatest>true</IsLatest><LastModified>2026-08-19T10:00:00Z</LastModified></Version>
  <Version><Key>ecommerce%2Fmanagement%2Fterraform.tfstate.extra</Key><VersionId>ignored</VersionId><IsLatest>false</IsLatest><LastModified>2026-08-18T10:00:00Z</LastModified></Version>
</ListVersionsResult>"""
        with tempfile.TemporaryDirectory(prefix="s3-xml-") as directory:
            fixture = Path(directory) / "response.xml"
            fixture.write_text(xml, encoding="utf-8")
            result = run(
                [
                    "python3",
                    "scripts/inspect-s3-version-history.py",
                    "parse-xml",
                    "--input",
                    str(fixture),
                    "--key",
                    KEY,
                ]
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            page = json.loads(result.stdout)
            self.assertEqual(len(page["entries"]), 1)
            self.assertNotIn("data", page["entries"][0])

    def test_s3_history_fixtures(self) -> None:
        expected = {
            "empty.json": "ZERO_HISTORY",
            "active-version.json": "HISTORICAL_STATE_PRESENT",
            "old-version-delete-marker.json": "HISTORICAL_STATE_PRESENT",
            "multiple-versions.json": "HISTORICAL_STATE_PRESENT",
            "api-error.json": "UNKNOWN",
            "ambiguous.json": "UNKNOWN",
        }
        fixture_root = ROOT / "tests/terraform-pg/s3-history"
        for name, verdict in expected.items():
            with self.subTest(name=name):
                result = run(
                    [
                        "python3",
                        "scripts/inspect-s3-version-history.py",
                        "evaluate",
                        "--input",
                        str(fixture_root / name),
                        "--key",
                        KEY,
                    ]
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(json.loads(result.stdout)["verdict"], verdict)

    def test_pg_target_fixtures(self) -> None:
        fixtures = ROOT / "tests/terraform-pg/pg-target"
        expected = {
            "empty.json": ("preflight", "EMPTY"),
            "non-empty.json": ("preflight", "NON_EMPTY"),
            "unknown.json": ("preflight", "UNKNOWN"),
            "post-init-empty-default.json": ("post-init", "EMPTY"),
        }
        for name, (phase, verdict) in expected.items():
            with self.subTest(name=name):
                result = run(
                    [
                        "python3",
                        "scripts/evaluate-terraform-pg-target.py",
                        "--input",
                        str(fixtures / name),
                        "--phase",
                        phase,
                    ]
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(json.loads(result.stdout)["verdict"], verdict)


if __name__ == "__main__":
    unittest.main(verbosity=2)
