#!/usr/bin/env python3
"""Offline tests for the external project environment contract."""

from __future__ import annotations

import os
import pwd
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
LOADER = ROOT / "scripts/run-with-project-env.py"
HELPER = ROOT / "scripts/init-project-secrets.sh"
SYSTEM_HOME = Path(pwd.getpwuid(os.geteuid()).pw_dir)
SYNTHETIC_IDENTITY = "AGE-" + "SECRET-" + "KEY-1" + ("A" * 58)
SYNTHETIC_RECIPIENT = "age1" + ("q" * 58)
SYNTHETIC_PASSWORD = "p" * 40


class ProjectEnvLoaderTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory(
            prefix="project-env-test-", dir=SYSTEM_HOME
        )
        self.parent = Path(self.directory.name)
        self.parent.chmod(0o700)
        self.env_file = self.parent / ".env"
        fake_bin = self.parent / "bin"
        fake_bin.mkdir(mode=0o700)
        fake_age_keygen = fake_bin / "age-keygen"
        fake_age_keygen.write_text(
            "#!/bin/sh\n"
            "[ \"${1:-}\" = '-y' ] || exit 2\n"
            "IFS= read -r supplied_identity\n"
            "case $supplied_identity in AGE-SECRET-KEY-1*) ;; *) exit 3 ;; esac\n"
            f"printf '%s\\n' '{SYNTHETIC_RECIPIENT}'\n",
            encoding="utf-8",
        )
        fake_age_keygen.chmod(0o700)
        self.environment = os.environ.copy()
        self.environment["PATH"] = f"{fake_bin}{os.pathsep}{self.environment.get('PATH', '')}"

    def tearDown(self) -> None:
        self.directory.cleanup()

    def contract(
        self,
        *,
        password: str | None = SYNTHETIC_PASSWORD,
        identity: str | None = SYNTHETIC_IDENTITY,
        recipient: str | None = SYNTHETIC_RECIPIENT,
        prefix: str = "# synthetic fixture\n\n",
    ) -> str:
        assignments: list[str] = []
        if password is not None:
            assignments.append(f"TERRAFORM_STATE_POSTGRESQL_PASSWORD={password}")
        if identity is not None:
            assignments.append(f"TERRAFORM_STATE_BACKUP_AGE_IDENTITY={identity}")
        if recipient is not None:
            assignments.append(f"TERRAFORM_STATE_BACKUP_AGE_RECIPIENT={recipient}")
        return prefix + "\n".join(assignments) + "\n"

    def write(self, content: str, mode: int = 0o600) -> None:
        self.env_file.write_text(content, encoding="utf-8")
        self.env_file.chmod(mode)

    def invoke(
        self,
        *,
        env_file: Path | None = None,
        command: list[str] | None = None,
    ) -> subprocess.CompletedProcess[str]:
        arguments = [
            "python3",
            str(LOADER),
            "--env-file",
            str(env_file or self.env_file),
        ]
        if command is None:
            arguments.append("--check-only")
        else:
            arguments.extend(["--", *command])
        return subprocess.run(
            arguments,
            cwd=ROOT,
            env=self.environment,
            text=True,
            capture_output=True,
            check=False,
        )

    def test_secure_file_comments_blank_lines_and_expected_variables_pass(self) -> None:
        self.write(self.contract(password=f"'{SYNTHETIC_PASSWORD}='"))
        result = self.invoke(
            command=[
                "python3",
                "-c",
                (
                    "import os,sys; "
                    "required=('TERRAFORM_STATE_POSTGRESQL_PASSWORD',"
                    "'TERRAFORM_STATE_BACKUP_AGE_IDENTITY',"
                    "'TERRAFORM_STATE_BACKUP_AGE_RECIPIENT'); "
                    "sys.exit(0 if all(os.environ.get(key) for key in required) else 1)"
                ),
            ]
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "")

    def test_missing_file_symlink_and_open_permissions_fail(self) -> None:
        missing = self.invoke(env_file=self.parent / "missing.env")
        self.assertNotEqual(missing.returncode, 0)

        target = self.parent / "target.env"
        target.write_text(self.contract(), encoding="utf-8")
        target.chmod(0o600)
        self.env_file.symlink_to(target)
        symlink = self.invoke()
        self.assertNotEqual(symlink.returncode, 0)
        self.env_file.unlink()

        self.write(self.contract(), mode=0o644)
        open_permissions = self.invoke()
        self.assertNotEqual(open_permissions.returncode, 0)

    def test_unsafe_parent_and_mnt_c_location_fail(self) -> None:
        self.write(self.contract())
        self.parent.chmod(0o755)
        unsafe_parent = self.invoke()
        self.assertNotEqual(unsafe_parent.returncode, 0)
        self.parent.chmod(0o700)

        forbidden_location = self.invoke(env_file=Path("/mnt/c/project-env-fixture/.env"))
        self.assertNotEqual(forbidden_location.returncode, 0)
        self.assertIn("forbidden location", forbidden_location.stderr)

    @unittest.skipUnless(os.geteuid() == 0, "wrong-owner fixture requires root")
    def test_wrong_owner_fails_when_testable(self) -> None:
        self.write(self.contract())
        os.chown(self.env_file, 65534, 65534)
        result = self.invoke()
        self.assertNotEqual(result.returncode, 0)

    def test_duplicate_invalid_and_malformed_assignments_fail(self) -> None:
        invalid_contracts = (
            self.contract() + "TERRAFORM_STATE_POSTGRESQL_PASSWORD=duplicate\n",
            self.contract() + "INVALID-KEY=value\n",
            self.contract() + "MALFORMED_LINE\n",
            self.contract() + 'QUOTED="unterminated\n',
        )
        for content in invalid_contracts:
            with self.subTest(content_type=invalid_contracts.index(content)):
                self.write(content)
                self.assertNotEqual(self.invoke().returncode, 0)

    def test_shell_like_value_is_data_and_is_never_executed(self) -> None:
        marker = self.parent / "must-not-exist"
        shell_like = f"$(touch {marker})" + ("x" * 32)
        self.write(self.contract(password=shell_like))
        result = self.invoke(command=["python3", "-c", "raise SystemExit(0)"])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(marker.exists())

    def test_required_values_length_match_and_placeholders_fail(self) -> None:
        invalid_contracts = (
            self.contract(password=None),
            self.contract(password="short"),
            self.contract(identity=None),
            self.contract(recipient=None),
            self.contract(recipient="age1" + ("z" * 58)),
            self.contract(password="REPLACE_" + ("x" * 40)),
            self.contract(identity="AGE-" + "SECRET-" + "KEY-1PLACEHOLDER" + ("A" * 40)),
            self.contract(recipient="age1replace" + ("q" * 50)),
        )
        for index, content in enumerate(invalid_contracts):
            with self.subTest(case=index):
                self.write(content)
                self.assertNotEqual(self.invoke().returncode, 0)


class ProjectSecretHelperStaticTests(unittest.TestCase):
    def test_helper_syntax_and_human_gate_contract(self) -> None:
        syntax = subprocess.run(
            ["sh", "-n", str(HELPER)],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(syntax.returncode, 0, syntax.stderr)
        source = HELPER.read_text(encoding="utf-8")
        for required in (
            ".config/ecommerce-1",
            "chmod 0700",
            "chmod 0600",
            "--force",
            "secrets.token_urlsafe(48)",
            "age-keygen -y",
            "run-with-project-env.py",
        ):
            self.assertIn(required, source)


if __name__ == "__main__":
    unittest.main()
