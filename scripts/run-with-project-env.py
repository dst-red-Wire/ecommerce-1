#!/usr/bin/env python3
"""Load the external project environment and exec a child without shell evaluation."""

from __future__ import annotations

import argparse
import os
import pwd
import re
import shutil
import stat
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PROJECT_ENV_PARTS = (".config", "ecommerce-1", ".env")
MAX_ENV_BYTES = 1024 * 1024
KEY_PATTERN = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")
AGE_IDENTITY_PATTERN = re.compile(r"AGE-SECRET-KEY-1[0-9A-Z]{40,}\Z")
AGE_RECIPIENT_PATTERN = re.compile(r"age1[0-9a-z]{20,}\Z")
PLACEHOLDER_MARKERS = ("REPLACE", "CHANGEME", "PLACEHOLDER", "EXAMPLE", "TODO")


class ProjectEnvError(Exception):
    """A fail-closed project environment contract violation."""


def real_home() -> Path:
    """Return the account home from the process identity, never from $HOME."""

    try:
        home = Path(pwd.getpwuid(os.geteuid()).pw_dir)
    except (KeyError, OSError) as error:
        raise ProjectEnvError("cannot determine the current account home") from error
    if not home.is_absolute():
        raise ProjectEnvError("the current account home is not absolute")
    return home


def default_env_path() -> Path:
    return real_home().joinpath(*PROJECT_ENV_PARTS)


def is_within(candidate: Path, parent: Path) -> bool:
    try:
        candidate.relative_to(parent)
    except ValueError:
        return False
    return True


def location_is_forbidden(candidate: Path) -> bool:
    candidate = Path(os.path.abspath(candidate))
    if is_within(candidate, ROOT):
        return True
    if is_within(candidate, Path("/mnt/c")) or is_within(candidate, Path("/tmp")):
        return True
    return any(part.casefold().startswith("onedrive") for part in candidate.parts)


def validate_location(requested: Path) -> Path:
    """Reject both the lexical path and its resolved destination when unsafe."""

    absolute = Path(os.path.abspath(requested))
    if location_is_forbidden(absolute):
        raise ProjectEnvError("the project environment path is in a forbidden location")
    resolved = absolute.resolve(strict=False)
    if location_is_forbidden(resolved):
        raise ProjectEnvError("the project environment resolves into a forbidden location")
    return absolute


def validate_parent(parent_fd: int) -> None:
    parent_status = os.fstat(parent_fd)
    parent_mode = stat.S_IMODE(parent_status.st_mode)
    if not stat.S_ISDIR(parent_status.st_mode):
        raise ProjectEnvError("the project environment parent is not a directory")
    if parent_status.st_uid != os.geteuid():
        raise ProjectEnvError("the project environment parent has the wrong owner")
    if parent_mode & ~0o700 or parent_mode & 0o500 != 0o500:
        raise ProjectEnvError(
            "the project environment parent must be mode 0700 or more restrictive"
        )


def read_secure_file(requested: Path) -> str:
    path = validate_location(requested)
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | nofollow
    file_flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | nofollow

    try:
        parent_fd = os.open(path.parent, directory_flags)
    except FileNotFoundError as error:
        raise ProjectEnvError("the project environment file is absent") from error
    except OSError as error:
        raise ProjectEnvError("the project environment parent is unsafe") from error

    try:
        validate_parent(parent_fd)
        try:
            file_fd = os.open(path.name, file_flags, dir_fd=parent_fd)
        except FileNotFoundError as error:
            raise ProjectEnvError("the project environment file is absent") from error
        except OSError as error:
            raise ProjectEnvError("the project environment file is unsafe") from error
        try:
            file_status = os.fstat(file_fd)
            file_mode = stat.S_IMODE(file_status.st_mode)
            if not stat.S_ISREG(file_status.st_mode):
                raise ProjectEnvError("the project environment must be a regular file")
            if file_status.st_uid != os.geteuid():
                raise ProjectEnvError("the project environment file has the wrong owner")
            if file_mode & ~0o600 or file_mode & 0o400 != 0o400:
                raise ProjectEnvError(
                    "the project environment file must be mode 0600 or more restrictive"
                )
            chunks: list[bytes] = []
            total = 0
            while True:
                chunk = os.read(file_fd, 65536)
                if not chunk:
                    break
                total += len(chunk)
                if total > MAX_ENV_BYTES:
                    raise ProjectEnvError("the project environment file is too large")
                chunks.append(chunk)
        finally:
            os.close(file_fd)
    finally:
        os.close(parent_fd)

    try:
        content = b"".join(chunks).decode("utf-8")
    except UnicodeDecodeError as error:
        raise ProjectEnvError("the project environment is not valid UTF-8") from error
    if "\x00" in content:
        raise ProjectEnvError("the project environment contains a NUL byte")
    return content


def parse_quoted_value(raw_value: str, line_number: int) -> str:
    quote = raw_value[0]
    output: list[str] = []
    index = 1
    while index < len(raw_value):
        character = raw_value[index]
        if character == quote:
            trailing = raw_value[index + 1 :].strip()
            if trailing and not trailing.startswith("#"):
                raise ProjectEnvError(f"malformed quoted value on line {line_number}")
            return "".join(output)
        if quote == '"' and character == "\\":
            index += 1
            if index >= len(raw_value):
                raise ProjectEnvError(f"malformed escape on line {line_number}")
            escaped = raw_value[index]
            escapes = {"\\": "\\", '"': '"', "n": "\n", "r": "\r", "t": "\t"}
            if escaped not in escapes:
                raise ProjectEnvError(f"unsupported escape on line {line_number}")
            output.append(escapes[escaped])
        else:
            output.append(character)
        index += 1
    raise ProjectEnvError(f"unterminated quoted value on line {line_number}")


def parse_project_env(content: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for line_number, line in enumerate(content.splitlines(), start=1):
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if "=" not in line:
            raise ProjectEnvError(f"malformed assignment on line {line_number}")
        raw_key, raw_value = line.split("=", 1)
        key = raw_key.strip()
        if not KEY_PATTERN.fullmatch(key):
            raise ProjectEnvError(f"invalid variable key on line {line_number}")
        if key in values:
            raise ProjectEnvError(f"duplicate variable key on line {line_number}")
        value = raw_value.strip()
        if value.startswith(("'", '"')):
            value = parse_quoted_value(value, line_number)
        values[key] = value
    return values


def is_placeholder(value: str) -> bool:
    upper_value = value.upper()
    return any(marker in upper_value for marker in PLACEHOLDER_MARKERS)


def require_secret_contract(values: dict[str, str]) -> None:
    password = values.get("TERRAFORM_STATE_POSTGRESQL_PASSWORD", "")
    identity = values.get("TERRAFORM_STATE_BACKUP_AGE_IDENTITY", "")
    recipient = values.get("TERRAFORM_STATE_BACKUP_AGE_RECIPIENT", "")

    if not password:
        raise ProjectEnvError("TERRAFORM_STATE_POSTGRESQL_PASSWORD is required")
    if len(password) < 32:
        raise ProjectEnvError("TERRAFORM_STATE_POSTGRESQL_PASSWORD must contain at least 32 characters")
    if is_placeholder(password):
        raise ProjectEnvError("TERRAFORM_STATE_POSTGRESQL_PASSWORD is a placeholder")
    if not identity:
        raise ProjectEnvError("TERRAFORM_STATE_BACKUP_AGE_IDENTITY is required")
    if is_placeholder(identity) or not AGE_IDENTITY_PATTERN.fullmatch(identity):
        raise ProjectEnvError("TERRAFORM_STATE_BACKUP_AGE_IDENTITY is invalid or a placeholder")
    if not recipient:
        raise ProjectEnvError("TERRAFORM_STATE_BACKUP_AGE_RECIPIENT is required")
    if is_placeholder(recipient) or not AGE_RECIPIENT_PATTERN.fullmatch(recipient):
        raise ProjectEnvError("TERRAFORM_STATE_BACKUP_AGE_RECIPIENT is invalid or a placeholder")

    age_keygen = shutil.which("age-keygen", path=os.environ.get("PATH"))
    if age_keygen is None:
        raise ProjectEnvError("age-keygen is required to validate the backup identity")
    try:
        derivation = subprocess.run(
            [age_keygen, "-y"],
            input=f"{identity}\n",
            text=True,
            capture_output=True,
            check=False,
            timeout=10,
            env={"PATH": os.environ.get("PATH", ""), "LANG": "C"},
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise ProjectEnvError("age recipient derivation failed") from error
    if derivation.returncode != 0:
        raise ProjectEnvError("age recipient derivation failed")
    derived_recipient = derivation.stdout.strip()
    if derived_recipient != recipient:
        raise ProjectEnvError("the age identity does not match the public recipient")


def load_project_env(path: Path) -> dict[str, str]:
    values = parse_project_env(read_secure_file(path))
    require_secret_contract(values)
    return values


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Validate the external project environment and exec a child process."
    )
    parser.add_argument(
        "--env-file",
        type=Path,
        help="secure external environment path (defaults to the canonical project path)",
    )
    parser.add_argument(
        "--check-only",
        action="store_true",
        help="validate the contract without executing a child process",
    )
    parser.add_argument("command", nargs=argparse.REMAINDER)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    command = args.command
    if command[:1] == ["--"]:
        command = command[1:]
    if args.check_only and command:
        raise ProjectEnvError("--check-only does not accept a child command")
    if not args.check_only and not command:
        raise ProjectEnvError("a child command is required after --")

    values = load_project_env(args.env_file or default_env_path())
    if args.check_only:
        print("Project secret contract: valid")
        return 0

    child_environment = os.environ.copy()
    child_environment.update(values)
    try:
        os.execvpe(command[0], command, child_environment)
    except OSError as error:
        raise ProjectEnvError("the child process could not be executed") from error


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ProjectEnvError as error:
        print(f"Project environment invalid: {error}", file=sys.stderr)
        raise SystemExit(1) from None
