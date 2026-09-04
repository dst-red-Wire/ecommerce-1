#!/usr/bin/env python3
"""Validate and prepare a bootstrap state tree without following symlinks."""

from __future__ import annotations

import argparse
import errno
import os
import pwd
import stat
from pathlib import Path


NON_OWNER_WRITE = stat.S_IWGRP | stat.S_IWOTH
DIRECTORY_OPEN_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC
FILE_OPEN_FLAGS = os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK


def fail(message: str) -> None:
    raise SystemExit(f"Bootstrap state path invalid: {message}")


def lexical_absolute(value: str, label: str) -> Path:
    if not os.path.isabs(value):
        fail(f"{label} must be absolute")
    return Path(os.path.abspath(value))


def require_below(path: Path, parent: Path, label: str) -> None:
    try:
        common = Path(os.path.commonpath((parent, path)))
    except ValueError:
        fail(f"{label} is outside its trusted parent")
    if common != parent or path == parent:
        fail(f"{label} must remain strictly below its trusted parent")


def validate_directory(
    metadata: os.stat_result,
    label: str,
    *,
    require_current_owner: bool,
    exact_mode: int | None = None,
) -> None:
    if not stat.S_ISDIR(metadata.st_mode):
        fail(f"{label} must be a directory")
    if require_current_owner and metadata.st_uid != os.geteuid():
        fail(f"{label} owner must equal the invoking user")
    if not require_current_owner and metadata.st_uid not in (0, os.geteuid()):
        fail(f"{label} owner must be root or the invoking user")
    mode = stat.S_IMODE(metadata.st_mode)
    if mode & NON_OWNER_WRITE:
        fail(f"{label} must not be writable by group or other")
    if exact_mode is not None and mode != exact_mode:
        fail(f"{label} permissions must equal {exact_mode:04o}")


def open_directory_at(parent_fd: int, name: str, label: str, *, create: bool) -> int:
    flags = DIRECTORY_OPEN_FLAGS | os.O_NOFOLLOW
    try:
        return os.open(name, flags, dir_fd=parent_fd)
    except FileNotFoundError:
        if not create:
            fail(f"{label} is unavailable")
        try:
            os.mkdir(name, 0o700, dir_fd=parent_fd)
            return os.open(name, flags, dir_fd=parent_fd)
        except FileExistsError:
            # A concurrent creator must still pass the non-following open.
            try:
                return os.open(name, flags, dir_fd=parent_fd)
            except OSError:
                fail(f"{label} changed during secure creation")
        except OSError:
            fail(f"{label} could not be created securely")
    except OSError as error:
        if error.errno in (errno.ELOOP, errno.ENOTDIR):
            fail(f"{label} contains a symbolic link or non-directory component")
        fail(f"{label} could not be opened securely")


def open_state_directory(
    trusted_home: Path,
    state_directory: Path,
    *,
    prepare: bool,
) -> int:
    home_parts = trusted_home.parts[1:]
    state_parts = state_directory.parts[1:]
    if state_parts[: len(home_parts)] != home_parts:
        fail("state directory must remain below the trusted home")

    current_fd = os.open("/", DIRECTORY_OPEN_FLAGS | os.O_NOFOLLOW)
    home_device: int | None = None
    try:
        validate_directory(
            os.fstat(current_fd),
            "system ancestor",
            require_current_owner=False,
        )
        for index, component in enumerate(state_parts, start=1):
            at_or_below_home = index >= len(home_parts)
            create = prepare and index > len(home_parts)
            next_fd = open_directory_at(
                current_fd,
                component,
                "controlled path component" if at_or_below_home else "system ancestor",
                create=create,
            )
            os.close(current_fd)
            current_fd = next_fd
            is_state_directory = index == len(state_parts)
            metadata = os.fstat(current_fd)
            if index == len(home_parts):
                home_device = metadata.st_dev
            elif index > len(home_parts) and metadata.st_dev != home_device:
                fail("controlled path must remain on the trusted home filesystem")
            validate_directory(
                metadata,
                "state directory" if is_state_directory else (
                    "controlled path component" if at_or_below_home else "system ancestor"
                ),
                require_current_owner=at_or_below_home,
                exact_mode=0o700 if is_state_directory else None,
            )
        return current_fd
    except BaseException:
        os.close(current_fd)
        raise


def validate_file_at(directory_fd: int, name: str, label: str, required: bool) -> None:
    try:
        descriptor = os.open(
            name,
            FILE_OPEN_FLAGS | os.O_NOFOLLOW,
            dir_fd=directory_fd,
        )
    except FileNotFoundError:
        if required:
            fail(f"{label} is unavailable")
        return
    except OSError as error:
        if error.errno == errno.ELOOP:
            fail(f"{label} must not be a symbolic link")
        fail(f"{label} must be a securely openable regular file")

    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            fail(f"{label} must be a regular file")
        if metadata.st_uid != os.geteuid():
            fail(f"{label} owner must equal the invoking user")
        if stat.S_IMODE(metadata.st_mode) != 0o600:
            fail(f"{label} permissions must equal 0600")
    finally:
        os.close(descriptor)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--allowed-root", required=True)
    parser.add_argument("--state-directory", required=True)
    parser.add_argument("--require-state", action="store_true")
    parser.add_argument("--prepare", action="store_true")
    args = parser.parse_args()

    if not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "O_DIRECTORY"):
        fail("this platform lacks required non-following directory operations")

    try:
        home_value = pwd.getpwuid(os.geteuid()).pw_dir
    except KeyError:
        fail("invoking user has no system home entry")
    trusted_home = lexical_absolute(home_value, "trusted system home")
    if trusted_home == Path("/"):
        fail("trusted system home must not be the filesystem root")
    home_parts = trusted_home.parts
    if (
        len(home_parts) >= 3
        and home_parts[1] == "mnt"
        and len(home_parts[2]) == 1
        and home_parts[2].isalpha()
    ):
        fail("trusted system home must remain outside Windows drive mounts")

    allowed_root = lexical_absolute(args.allowed_root, "allowed XDG state root")
    state_directory = lexical_absolute(args.state_directory, "state directory")
    require_below(allowed_root, trusted_home, "allowed XDG state root")
    require_below(state_directory, allowed_root, "state directory")

    state_fd = open_state_directory(
        trusted_home,
        state_directory,
        prepare=args.prepare,
    )
    try:
        terraform_data_fd = open_directory_at(
            state_fd,
            "terraform-data",
            "Terraform data directory",
            create=args.prepare,
        )
        try:
            validate_directory(
                os.fstat(terraform_data_fd),
                "Terraform data directory",
                require_current_owner=True,
                exact_mode=0o700,
            )
        finally:
            os.close(terraform_data_fd)

        validate_file_at(
            state_fd,
            "terraform.tfstate",
            "authoritative bootstrap state",
            args.require_state,
        )
        validate_file_at(
            state_fd,
            "terraform.tfstate.backup",
            "authoritative bootstrap state backup",
            False,
        )
    finally:
        os.close(state_fd)


if __name__ == "__main__":
    main()
