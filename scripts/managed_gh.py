"""Resolve the registry-managed GitHub CLI from its hash-pinned release archive."""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import tarfile
from pathlib import Path
from typing import Mapping


def _default_probe_environment() -> dict[str, str]:
    """Run unauthenticated capability probes without inherited tools or secrets."""
    return {
        "PATH": "/usr/bin:/bin",
        "HOME": "/nonexistent",
        "XDG_CONFIG_HOME": "/nonexistent",
        "GH_PROMPT_DISABLED": "1",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_SYSTEM": "/dev/null",
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_CONFIG_COUNT": "4",
        "GIT_CONFIG_KEY_0": "core.fsmonitor",
        "GIT_CONFIG_VALUE_0": "false",
        "GIT_CONFIG_KEY_1": "core.hooksPath",
        "GIT_CONFIG_VALUE_1": "/dev/null",
        "GIT_CONFIG_KEY_2": "credential.helper",
        "GIT_CONFIG_VALUE_2": "",
        "GIT_CONFIG_KEY_3": "protocol.ext.allow",
        "GIT_CONFIG_VALUE_3": "never",
    }


def resolve_managed_gh(
    root: Path, *, env: Mapping[str, str] | None = None
) -> tuple[str, str, str]:
    """Prove the managed gh binary came from the hash-pinned registry archive."""
    environment = os.environ if env is None else env
    probe_environment = _default_probe_environment() if env is None else env
    try:
        lock = json.loads((root / "config/contracts/toolchain-lock.json").read_text(encoding="utf-8"))
        versions = lock["versions"]
        install = lock["capability_policy"]["managed_install_root"]
        active = lock["tool_lifecycle"]["active"]["gh"]
        version = versions["GH_VERSION"]
        archive_sha256 = versions["GH_SHA256_LINUX_AMD64_TARGZ"]
        if (not isinstance(version, str)
            or re.fullmatch(r"[0-9]+[.][0-9]+[.][0-9]+", version) is None
            or not isinstance(archive_sha256, str)
            or re.fullmatch(r"[0-9a-f]{64}", archive_sha256) is None
            or active.get("version_ref") != "GH_VERSION"
            or active.get("checksum_ref") != "GH_SHA256_LINUX_AMD64_TARGZ"
            or active.get("provision") != {"type": "ansible", "tags": "gh"}):
            raise ValueError("managed gh registry projection is invalid")
        keys = ("environment", "fallback", "bin_subdirectory",
                "share_subdirectory", "cache_subdirectory", "fallback_cache_root")
        if any(not isinstance(install.get(key), str) or not install[key]
               for key in keys):
            raise ValueError("managed gh install root policy is invalid")
        configured = environment.get(install["environment"], "").strip()
        root = Path(configured or install["fallback"]).expanduser()
        cache = (root / install["cache_subdirectory"] if configured
                 else Path(install["fallback_cache_root"]).expanduser())
        if not root.is_absolute() or not cache.is_absolute():
            raise ValueError("managed gh install or cache root is not absolute")
        root = root.resolve(strict=True)
        link = root / install["bin_subdirectory"] / "gh"
        binary = root / install["share_subdirectory"] / "tools" / f"gh-{version}" / "bin" / "gh"
        archive = cache / f"gh-{version}-linux-amd64.tar.gz"
        if (not link.is_symlink() or link.resolve(strict=True) != binary
            or binary.is_symlink() or not binary.is_file()
            or not os.access(binary, os.X_OK)
            or any(character.isspace() or character in {'"', "'"}
                   for character in str(binary))):
            raise ValueError("managed gh executable is absent or redirected")

        def file_digest(source: Path) -> str:
            digest = hashlib.sha256()
            with source.open("rb") as stream:
                for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                    digest.update(chunk)
            return digest.hexdigest()

        if file_digest(archive) != archive_sha256:
            raise ValueError("managed gh archive checksum differs from the registry")
        member_name = f"gh_{version}_linux_amd64/bin/gh"
        with tarfile.open(archive, "r:gz") as package:
            member = package.getmember(member_name)
            if not member.isfile():
                raise ValueError("managed gh archive binary is not regular")
            stream = package.extractfile(member)
            if stream is None:
                raise ValueError("managed gh archive binary is unreadable")
            digest = hashlib.sha256()
            with stream:
                for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                    digest.update(chunk)
            binary_sha256 = digest.hexdigest()
        if file_digest(binary) != binary_sha256:
            raise ValueError("managed gh binary differs from pinned archive")
        version_check = subprocess.run(
            [str(binary), "--version"], env=probe_environment, capture_output=True,
            text=True, check=False, timeout=20)
        help_check = subprocess.run(
            [str(binary), "api", "--help"], env=probe_environment, capture_output=True,
            text=True, check=False, timeout=20)
        first_line = version_check.stdout.splitlines()
        if (version_check.returncode != 0 or not first_line
            or re.match(r"^gh version " + re.escape(version) + r"(?:[ (]|$)",
                        first_line[0]) is None
            or help_check.returncode != 0
            or "--slurp" not in help_check.stdout
            or "--paginate" not in help_check.stdout):
            raise ValueError("managed gh version or API capabilities differ from registry")
        return str(binary), version, binary_sha256
    except (OSError, KeyError, TypeError, ValueError, RuntimeError,
            tarfile.TarError, subprocess.TimeoutExpired) as exc:
        raise ValueError(f"managed gh is unavailable: {exc}") from exc

