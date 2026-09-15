#!/usr/bin/env python3
"""Install the small gate tool closure into the checkout deterministically."""

from __future__ import annotations

import argparse
import hashlib
import os
from pathlib import Path
import platform
import shutil
import subprocess
import tarfile
import tempfile
import urllib.request


ROOT = Path(__file__).resolve().parents[1]
VERSIONS_FILE = ROOT / "config/toolchain/versions.env"
TOOLS_ROOT = ROOT / ".tools"


def load_versions(path: Path | None = None) -> dict[str, str]:
    path = path or VERSIONS_FILE
    values: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            key, separator, value = line.partition("=")
            if not separator or not key or not value:
                raise RuntimeError(f"invalid tool version authority line: {line!r}")
            values[key] = value
    return values


def normalized_platform() -> tuple[str, str]:
    os_name = platform.system().lower()
    machine = platform.machine().lower()
    architectures = {"x86_64": "amd64", "amd64": "amd64", "aarch64": "arm64", "arm64": "arm64"}
    if os_name != "linux" or machine not in architectures:
        raise RuntimeError(f"unsupported repository tool platform: {os_name}/{machine}")
    return os_name, architectures[machine]


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _download(url: str, destination: Path, expected: str) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_name(f".{destination.name}.{os.getpid()}.tmp")
    try:
        with urllib.request.urlopen(url, timeout=60) as response, temporary.open("wb") as output:
            shutil.copyfileobj(response, output)
        actual = sha256(temporary)
        if actual != expected:
            raise RuntimeError(f"checksum mismatch for {destination.name}: expected {expected}, got {actual}")
        os.replace(temporary, destination)
    finally:
        temporary.unlink(missing_ok=True)


def _verified_cache(url: str, destination: Path, expected: str) -> Path:
    if destination.is_file():
        actual = sha256(destination)
        if actual == expected:
            return destination
        raise RuntimeError(f"checksum mismatch for cached {destination.name}: expected {expected}, got {actual}")
    _download(url, destination, expected)
    return destination


def _version_matches(binary: Path, arguments: list[str], version: str) -> bool:
    if not binary.is_file() or not os.access(binary, os.X_OK):
        return False
    result = subprocess.run([str(binary), *arguments], text=True, capture_output=True, check=False)
    return result.returncode == 0 and version in (result.stdout + result.stderr)


def _install_file(source: Path, destination: Path, expected_binary_sha: str) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_name(f".{destination.name}.{os.getpid()}.tmp")
    shutil.copyfile(source, temporary)
    if sha256(temporary) != expected_binary_sha:
        temporary.unlink(missing_ok=True)
        raise RuntimeError(f"installed binary checksum mismatch for {destination.name}")
    temporary.chmod(0o755)
    os.replace(temporary, destination)


def provision(tool_names: tuple[str, ...] = ("yq", "oasdiff")) -> None:
    values = load_versions()
    os_name, arch = normalized_platform()
    bin_dir, cache_dir = TOOLS_ROOT / "bin", TOOLS_ROOT / "cache"
    specifications = {
        "yq": {
            "version": values["YQ_VERSION"],
            "url": f"https://github.com/mikefarah/yq/releases/download/v{values['YQ_VERSION']}/yq_{os_name}_{arch}",
            "archive_sha": values[f"YQ_SHA256_{os_name.upper()}_{arch.upper()}"],
            "binary_sha": values[f"YQ_SHA256_{os_name.upper()}_{arch.upper()}"],
            "version_args": ["--version"],
            "archive": False,
        },
        "oasdiff": {
            "version": values["OASDIFF_VERSION"],
            "url": f"https://github.com/oasdiff/oasdiff/releases/download/v{values['OASDIFF_VERSION']}/oasdiff_{values['OASDIFF_VERSION']}_{os_name}_{arch}.tar.gz",
            "archive_sha": values[f"OASDIFF_SHA256_{os_name.upper()}_{arch.upper()}_TARGZ"],
            "binary_sha": values[f"OASDIFF_BINARY_SHA256_{os_name.upper()}_{arch.upper()}"],
            "version_args": ["--version"],
            "archive": True,
        },
    }
    unknown = set(tool_names) - set(specifications)
    if unknown:
        raise RuntimeError(f"unknown repository tools: {', '.join(sorted(unknown))}")
    for name in tool_names:
        spec = specifications[name]
        binary = bin_dir / name
        binary_is_verified = binary.is_file() and sha256(binary) == spec["binary_sha"]
        if binary_is_verified:
            if _version_matches(binary, spec["version_args"], spec["version"]):
                print(f"PASS repository tool {name} {spec['version']} (cached)")
                continue
        suffix = ".tar.gz" if spec["archive"] else ""
        cached = _verified_cache(spec["url"], cache_dir / f"{name}-{spec['version']}-{os_name}-{arch}{suffix}", spec["archive_sha"])
        if spec["archive"]:
            with tempfile.TemporaryDirectory(dir=TOOLS_ROOT) as directory:
                with tarfile.open(cached, "r:gz") as archive:
                    member = next((item for item in archive.getmembers() if item.name == name and item.isfile()), None)
                    if member is None:
                        raise RuntimeError(f"release archive does not contain {name}")
                    extracted = archive.extractfile(member)
                    if extracted is None:
                        raise RuntimeError(f"release archive cannot extract {name}")
                    with (Path(directory) / name).open("wb") as output:
                        shutil.copyfileobj(extracted, output)
                _install_file(Path(directory) / name, binary, spec["binary_sha"])
        else:
            _install_file(cached, binary, spec["binary_sha"])
        if not _version_matches(binary, spec["version_args"], spec["version"]):
            raise RuntimeError(f"installed {name} does not report pinned version {spec['version']}")
        print(f"PASS repository tool {name} {spec['version']} (provisioned)")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("tools", nargs="*", choices=("yq", "oasdiff"))
    args = parser.parse_args()
    try:
        provision(tuple(args.tools) or ("yq", "oasdiff"))
    except (OSError, RuntimeError, tarfile.TarError) as exc:
        print(f"FAIL repository tools: {exc}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
